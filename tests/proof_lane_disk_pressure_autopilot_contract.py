#!/usr/bin/env python3
"""End-to-end golden contract for disk-pressure proof-lane handoff."""

import json
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures" / "proof_lane_disk_pressure_autopilot"
GENERATED_AT = "2026-05-18T21:25:00Z"
RCH_COMMAND = (
    "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_beigesnow_autopilot "
    "cargo test -p asupersync --test reservation_aware_work_finder_contract"
)


def run_json(command: list[str]) -> dict:
    completed = subprocess.run(
        command,
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


def run_rch_receipt() -> dict:
    return run_json(
        [
            "python3",
            str(REPO_ROOT / "scripts" / "rch_retrieval_receipt.py"),
            "--log",
            str(FIXTURE_ROOT / "rch_remote_pass_enospc.log"),
            "--command",
            RCH_COMMAND,
            "--generated-at",
            GENERATED_AT,
            "--wrapper-exit-code",
            "1",
            "--proof-lane",
            "disk-pressure-autopilot",
            "--guarantee",
            "remote proof verdict is separated from local artifact retrieval",
            "--artifact-free-proof-receipt",
            "--output",
            "json",
        ]
    )


def run_work_finder() -> dict:
    return run_json(
        [
            "python3",
            str(REPO_ROOT / "scripts" / "reservation_aware_work_finder.py"),
            "--fixture",
            str(FIXTURE_ROOT / "work_finder_source.json"),
            "--repo-path",
            str(REPO_ROOT),
            "--agent",
            "BeigeSnow",
            "--generated-at",
            GENERATED_AT,
            "--output",
            "json",
        ]
    )


def run_inventory() -> dict:
    return run_json(
        [
            "python3",
            str(REPO_ROOT / "scripts" / "rch_target_inventory.py"),
            "--source",
            str(FIXTURE_ROOT / "rch_targets.json"),
            "--generated-at",
            GENERATED_AT,
            "--output",
            "json",
        ]
    )


def cleanup_table(inventory: dict) -> list[dict]:
    return [
        {
            "path": row["path"],
            "classification": row["classification"],
            "authorization_candidate": row["authorization_candidate"],
            "size_bytes": row["size_bytes"],
            "reason": row["reason"],
        }
        for row in inventory["candidates"]
        if row["authorization_candidate"]
    ]


def build_handoff(work_finder: dict, rch_receipt: dict, inventory: dict) -> dict:
    proof = rch_receipt["artifact_free_proof_receipt"]
    return {
        "schema_version": "proof-lane-disk-pressure-autopilot-handoff-v1",
        "agent": work_finder["agent"],
        "active_dirty_paths": work_finder["dirty_paths"],
        "chosen_next_lane": work_finder["recommendation"],
        "remote_proof_result": proof["remote_command_result"],
        "artifact_retrieval_result": proof["artifact_retrieval_result"],
        "disk_pressure": {
            "work_finder_level": work_finder["disk_pressure"]["level"],
            "work_finder_available_bytes": work_finder["disk_pressure"]["available_bytes"],
            "rch_heavy_work_allowed": work_finder["disk_pressure"]["rch_heavy_work_allowed"],
            "receipt_local_status": proof["local_disk_pressure"]["status"],
            "receipt_signal": proof["local_disk_pressure"]["signal"],
        },
        "cleanup_candidates": cleanup_table(inventory),
        "cleanup_summary": inventory["summary"],
        "deletion_policy": {
            "requires_user_authorization": True,
            "delete_command_available": inventory["deletion_command_available"],
            "work_finder_mutating_commands_executed": work_finder["safety"][
                "mutating_commands_executed"
            ],
            "instruction": (
                "Deletion requires explicit user authorization; this fixture never "
                "runs rm, git clean, or cleanup automation."
            ),
        },
    }


class DiskPressureAutopilotGoldenContract(unittest.TestCase):
    maxDiff = None

    def test_autopilot_handoff_matches_golden(self) -> None:
        handoff = build_handoff(
            work_finder=run_work_finder(),
            rch_receipt=run_rch_receipt(),
            inventory=run_inventory(),
        )
        expected = json.loads((FIXTURE_ROOT / "handoff_expected.json").read_text())

        self.assertEqual(handoff, expected)
        self.assertEqual(handoff["chosen_next_lane"]["category"], "claim-ready-bead")
        self.assertFalse(handoff["disk_pressure"]["rch_heavy_work_allowed"])
        self.assertEqual(handoff["remote_proof_result"]["status"], "pass")
        self.assertEqual(handoff["artifact_retrieval_result"]["status"], "blocked")
        self.assertTrue(handoff["cleanup_candidates"])
        self.assertFalse(handoff["deletion_policy"]["delete_command_available"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
