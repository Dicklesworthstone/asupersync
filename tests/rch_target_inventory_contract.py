#!/usr/bin/env python3
"""Contract tests for the report-only rch target inventory helper."""

import json
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "rch_target_inventory.py"
FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures" / "rch_target_inventory"
GENERATED_AT = "2026-05-18T20:00:00Z"


class RchTargetInventoryContract(unittest.TestCase):
    def run_inventory(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(SCRIPT), *args],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def inventory_json(self, fixture: str) -> dict:
        output = self.run_inventory(
            "--source",
            str(FIXTURE_ROOT / fixture),
            "--generated-at",
            GENERATED_AT,
            "--output",
            "json",
        )
        self.assertEqual(output.returncode, 0, output.stderr)
        return json.loads(output.stdout)

    def test_help_exposes_no_cleanup_flags(self) -> None:
        output = self.run_inventory("--help")

        self.assertEqual(output.returncode, 0, output.stderr)
        for forbidden in ("--delete", "--clean", "--rm", "--yes", "--force"):
            self.assertNotIn(forbidden, output.stdout)

    def test_mixed_candidates_match_golden(self) -> None:
        actual = self.inventory_json("mixed_candidates.json")
        expected = json.loads((FIXTURE_ROOT / "mixed_candidates_expected.json").read_text())

        self.assertEqual(actual, expected)
        self.assertTrue(actual["non_mutating"])
        self.assertFalse(actual["deletion_command_available"])

    def test_text_summary_names_authorization_candidates(self) -> None:
        output = self.run_inventory(
            "--source",
            str(FIXTURE_ROOT / "mixed_candidates.json"),
            "--generated-at",
            GENERATED_AT,
            "--output",
            "text",
        )

        self.assertEqual(output.returncode, 0, output.stderr)
        self.assertIn("Expected recovered with authorization: 2.0 GiB", output.stdout)
        self.assertIn("AUTH stale-looking 2.0 GiB /tmp/rch_target_stale_beigesnow", output.stdout)
        self.assertIn("SKIP active-looking", output.stdout)
        self.assertIn("SKIP permission-denied", output.stdout)
        self.assertIn("SKIP missing", output.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
