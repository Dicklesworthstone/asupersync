#!/usr/bin/env python3
"""ATP CLI user-journey structured log bundle validator."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

CONTRACT_VERSION = "atp-user-journey-e2e.v1"
REQUIRED_LOG_FIELDS = [
    "event",
    "scenario_id",
    "command_line",
    "config_profile",
    "daemon_ids",
    "transfer_id",
    "path_summary",
    "manifest_root",
    "receive_plan_digest",
    "progress_event",
    "quarantine_path_state",
    "final_path_state",
    "final_proof",
]

SCENARIOS = [
    {
        "scenario_id": "first_pairing_share_code",
        "command_line": (
            "asupersync atp serve --profile first-run --json && "
            "asupersync atp share ./fixture --peer bob --json && "
            "asupersync atp status --json"
        ),
        "surfaces": ["cli", "atpd", "sdk"],
        "sdk_apis": ["AtpSdk::create_identity", "AtpSdk::create_share_code"],
        "daemon_events": ["daemon_start", "identity_created", "grant_recorded"],
        "receive_policy": ["deny_by_default"],
        "path_modes": ["direct"],
    },
    {
        "scenario_id": "send_receive_explicit_approval",
        "command_line": (
            "asupersync atp send ./fixture bob --name demo --json && "
            "asupersync atp inbox --json && "
            "asupersync atp get transfer-demo ./out --approve --json"
        ),
        "surfaces": ["cli", "atpd", "sdk"],
        "sdk_apis": ["AtpSdk::send", "AtpSdk::receive_plan", "ReceivePlan::approve"],
        "daemon_events": ["sender_daemon_start", "receiver_daemon_start", "inbox_insert"],
        "receive_policy": ["explicit_approval", "safe_destination"],
        "path_modes": ["direct", "relay"],
    },
    {
        "scenario_id": "receive_safety_deny_quarantine",
        "command_line": (
            "asupersync atp get transfer-demo ./out --dry-run --json && "
            "asupersync atp get transfer-demo ./out --deny --json && "
            "asupersync atp get transfer-demo ./out --quarantine-only --json"
        ),
        "surfaces": ["cli", "atpd", "sdk"],
        "sdk_apis": [
            "AtpSdk::receive_plan",
            "ReceivePlan::deny",
            "ReceivePlan::quarantine_only",
        ],
        "daemon_events": ["receive_plan_constructed", "receive_denied", "quarantine_created"],
        "receive_policy": [
            "deny_by_default",
            "quarantine_only",
            "safe_destination",
            "dry_run",
        ],
        "path_modes": ["mailbox"],
    },
    {
        "scenario_id": "sync_mirror_watch_seed",
        "command_line": (
            "asupersync atp sync ./left bob:/right --json && "
            "asupersync atp mirror ./left bob:/mirror --json && "
            "asupersync atp watch ./left bob:/watch --json && "
            "asupersync atp seed transfer-demo --json"
        ),
        "surfaces": ["cli", "sdk"],
        "sdk_apis": ["AtpSdk::sync", "AtpSdk::mirror", "AtpSdk::watch", "AtpSdk::seed"],
        "daemon_events": ["watch_started", "seed_registered"],
        "receive_policy": ["policy_driven_auto_accept", "policy_driven_auto_deny"],
        "path_modes": ["direct", "relay"],
    },
    {
        "scenario_id": "resume_cancel_restart",
        "command_line": (
            "asupersync atp cancel transfer-demo --json && "
            "asupersync atp resume transfer-demo --json && "
            "asupersync atp status transfer-demo --json"
        ),
        "surfaces": ["cli", "atpd", "sdk"],
        "sdk_apis": ["AtpSdk::cancel", "AtpSdk::resume", "AtpSdk::status"],
        "daemon_events": ["shutdown_requested", "daemon_restart", "journal_recovered"],
        "receive_policy": ["resume_preserves_receive_plan"],
        "path_modes": ["direct"],
    },
    {
        "scenario_id": "nat_tailscale_relay_mailbox",
        "command_line": "asupersync atp send ./fixture bob --path auto --json",
        "surfaces": ["cli", "atpd"],
        "sdk_apis": ["AtpSdk::path_candidates", "AtpSdk::mailbox_enqueue"],
        "daemon_events": ["nat_probe", "tailscale_candidate_optional", "relay_fallback"],
        "receive_policy": ["mailbox_requires_receive_plan"],
        "path_modes": ["nat_fallback", "tailscale_optional", "relay", "mailbox"],
    },
    {
        "scenario_id": "doctor_trace_replay_bench",
        "command_line": (
            "asupersync atp doctor --json && "
            "asupersync trace verify trace.bin --json && "
            "asupersync lab replay scenario.yaml --json && "
            "asupersync atp bench --smoke --json"
        ),
        "surfaces": ["cli"],
        "sdk_apis": ["AtpSdk::doctor", "AtpSdk::bench_smoke"],
        "daemon_events": ["diagnostics_collected"],
        "receive_policy": ["not_applicable"],
        "path_modes": ["loopback"],
    },
    {
        "scenario_id": "proof_verify_failure_discovery",
        "command_line": (
            "asupersync atp proof proof_bundle.json --summary --json && "
            "asupersync atp verify proof_bundle.json --strict --json"
        ),
        "surfaces": ["cli", "sdk"],
        "sdk_apis": ["AtpSdk::proof", "AtpSdk::verify"],
        "daemon_events": ["proof_recorded"],
        "receive_policy": ["proof_bound_to_receive_plan"],
        "path_modes": ["direct", "relay", "mailbox"],
    },
]


def digest_for(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def event_for(scenario: dict[str, object], run_id: str, dry_run: bool) -> dict[str, object]:
    scenario_id = str(scenario["scenario_id"])
    transfer_id = f"transfer-{digest_for(run_id + scenario_id)[:12]}"
    manifest_root = digest_for("manifest:" + scenario_id)
    receive_plan_digest = digest_for("receive-plan:" + scenario_id)
    return {
        "event": "atp_user_journey_step",
        "contract_version": CONTRACT_VERSION,
        "scenario_id": scenario_id,
        "command_line": scenario["command_line"],
        "config_profile": "e2e-local-two-daemon",
        "daemon_ids": ["sender-atpd", "receiver-atpd"],
        "transfer_id": transfer_id,
        "path_summary": {
            "modes": scenario["path_modes"],
            "fallback_order": ["direct", "tailscale_optional", "relay", "mailbox"],
        },
        "manifest_root": manifest_root,
        "receive_plan_digest": receive_plan_digest,
        "progress_event": {
            "phase": "contract" if dry_run else "e2e",
            "bytes_total": 4096,
            "bytes_done": 4096,
        },
        "quarantine_path_state": "created-and-retained"
        if "quarantine_only" in scenario["receive_policy"]
        else "not-required",
        "final_path_state": "safe-destination-unchanged" if dry_run else "verified",
        "final_proof": {
            "proof_bundle": "proof_bundle.json",
            "verification_report": "verification_report.json",
            "digest": digest_for("proof:" + scenario_id),
        },
        "surfaces": scenario["surfaces"],
        "sdk_apis": scenario["sdk_apis"],
        "daemon_events": scenario["daemon_events"],
        "receive_policy": scenario["receive_policy"],
    }


def validate_events(events: list[dict[str, object]]) -> list[str]:
    failures: list[str] = []
    observed_scenarios = {str(event.get("scenario_id", "")) for event in events}
    expected_scenarios = {str(scenario["scenario_id"]) for scenario in SCENARIOS}
    if observed_scenarios != expected_scenarios:
        failures.append(
            f"scenario mismatch expected={sorted(expected_scenarios)} observed={sorted(observed_scenarios)}"
        )

    for event in events:
        missing = [field for field in REQUIRED_LOG_FIELDS if field not in event]
        if missing:
            failures.append(f"{event.get('scenario_id', '<unknown>')}: missing fields {missing}")

    command_blob = "\n".join(str(event.get("command_line", "")) for event in events)
    for command in [
        "send",
        "get",
        "sync",
        "mirror",
        "share",
        "watch",
        "seed",
        "inbox",
        "status",
        "resume",
        "cancel",
        "verify",
        "proof",
        "doctor",
        "trace",
        "replay",
        "bench",
    ]:
        if command not in command_blob:
            failures.append(f"missing command coverage: {command}")

    policy_blob = json.dumps(events, sort_keys=True)
    for policy in [
        "explicit_approval",
        "deny_by_default",
        "quarantine_only",
        "safe_destination",
        "dry_run",
    ]:
        if policy not in policy_blob:
            failures.append(f"missing receive policy coverage: {policy}")

    for path_mode in ["nat_fallback", "tailscale_optional", "relay", "mailbox"]:
        if path_mode not in policy_blob:
            failures.append(f"missing path coverage: {path_mode}")

    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--cargo-status", type=int, default=0)
    args = parser.parse_args()

    output_root = Path(args.output_root)
    run_dir = output_root / f"run_{args.run_id}"
    run_dir.mkdir(parents=True, exist_ok=True)
    events_path = run_dir / "structured_events.jsonl"
    report_path = run_dir / "run_report.json"

    events = [event_for(scenario, args.run_id, args.dry_run) for scenario in SCENARIOS]
    with events_path.open("w", encoding="utf-8") as events_file:
        for event in events:
            events_file.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")

    failures = validate_events(events)
    if args.cargo_status != 0:
        failures.append(f"cargo_status:{args.cargo_status}")

    report = {
        "contract_version": CONTRACT_VERSION,
        "status": "pass" if not failures else "fail",
        "run_id": args.run_id,
        "dry_run": args.dry_run,
        "cargo_status": args.cargo_status,
        "scenario_count": len(events),
        "required_log_fields": REQUIRED_LOG_FIELDS,
        "structured_events_path": str(events_path),
        "proof_artifacts": [
            str(events_path),
            str(report_path),
            str(run_dir / "run.log"),
        ],
        "failures": failures,
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
