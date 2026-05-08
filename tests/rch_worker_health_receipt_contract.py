#!/usr/bin/env python3
"""Contract tests for scripts/rch_worker_health_receipt.py."""

import json
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "rch_worker_health_receipt.py"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "rch_worker_health_receipt"
GENERATED_AT = "2026-05-08T05:40:00Z"


def fixture_arg(fixture: str) -> str:
    return f"tests/fixtures/rch_worker_health_receipt/{fixture}"


def fixture_text(fixture: str) -> str:
    return (FIXTURES / fixture).read_text(encoding="utf-8")


def run_receipt_output(fixture: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--observations",
            fixture_arg(fixture),
            "--generated-at",
            GENERATED_AT,
            "--output",
            "json",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


def run_receipt(fixture: str) -> dict:
    output = run_receipt_output(fixture)
    return json.loads(output.stdout)


class RchWorkerHealthReceiptContract(unittest.TestCase):
    def test_healthy_worker_is_eligible_for_normal_lanes(self) -> None:
        receipt = run_receipt("healthy_worker.json")

        self.assertEqual(receipt["schema_version"], "rch-worker-health-receipt-v1")
        self.assertEqual(receipt["generated_at"], GENERATED_AT)
        self.assertEqual(receipt["current_date"], "2026-05-08")
        self.assertEqual(receipt["fleet_status"], "healthy")
        self.assertEqual(receipt["workers"][0]["status"], "healthy")
        self.assertIn("eligible", receipt["workers"][0]["remediation"][0])

    def test_retrieval_stall_warns_before_quarantine_threshold(self) -> None:
        receipt = run_receipt("single_retrieval_timeout.json")

        self.assertEqual(receipt["fleet_status"], "degraded")
        self.assertEqual(receipt["workers"][0]["status"], "warn")
        self.assertEqual(receipt["workers"][0]["signals"]["retrieval_timeout"], 1)
        self.assertIn("single artifact retrieval timeout", receipt["workers"][0]["reasons"])

    def test_repeated_remote_failures_are_quarantine_candidates(self) -> None:
        receipt = run_receipt("repeated_remote_failures.json")

        self.assertEqual(receipt["workers"][0]["status"], "quarantine-candidate")
        self.assertEqual(receipt["workers"][0]["signals"]["remote_failure"], 2)
        self.assertIn("repeated remote command failures", receipt["workers"][0]["reasons"])
        self.assertIn("avoid scheduling expensive cargo lanes", receipt["workers"][0]["remediation"][0])

    def test_low_tmp_storage_is_quarantine_candidate(self) -> None:
        receipt = run_receipt("low_tmp_storage.json")

        self.assertEqual(receipt["workers"][0]["status"], "quarantine-candidate")
        self.assertIn("low storage on /tmp", receipt["workers"][0]["reasons"])

    def test_unreachable_worker_is_unavailable(self) -> None:
        receipt = run_receipt("unreachable_worker.json")

        self.assertEqual(receipt["fleet_status"], "unavailable")
        self.assertEqual(receipt["workers"][0]["status"], "unavailable")
        self.assertFalse(receipt["workers"][0]["signals"]["reachable"])
        self.assertIn("rch workers probe --all", receipt["workers"][0]["remediation"][0])

    def test_mixed_fleet_prefers_healthy_worker_but_marks_degraded(self) -> None:
        receipt = run_receipt("mixed_fleet.json")

        self.assertEqual(receipt["fleet_status"], "degraded")
        self.assertEqual(receipt["source_counts"]["workers"], 3)
        self.assertEqual(receipt["status_counts"]["healthy"], 1)
        self.assertEqual(receipt["status_counts"]["warn"], 1)
        self.assertEqual(receipt["status_counts"]["quarantine-candidate"], 1)

    def test_mixed_fleet_output_matches_full_reviewed_golden(self) -> None:
        output = run_receipt_output("mixed_fleet.json")
        expected = fixture_text("mixed_fleet_expected.json")

        self.assertEqual(
            output.stdout,
            expected,
            "mixed fleet rch worker health receipt drifted from the reviewed golden",
        )
        json.loads(output.stdout)
        json.loads(expected)

    def test_helper_declares_it_does_not_mutate_or_probe(self) -> None:
        receipt = run_receipt("healthy_worker.json")

        self.assertTrue(receipt["non_mutating"])
        for key in (
            "runs_rch",
            "runs_ssh",
            "runs_cargo",
            "runs_git_mutation",
            "runs_beads_mutation",
            "runs_destructive_command",
        ):
            self.assertFalse(receipt["forbidden_actions"][key], key)
        self.assertIn("does not probe live workers", receipt["safety_notes"][0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
