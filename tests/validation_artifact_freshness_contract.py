#!/usr/bin/env python3
"""Contract tests for scripts/validation_artifact_freshness.py."""

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "validation_artifact_freshness.py"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "validation_artifact_freshness"
FIXTURES_REL = "tests/fixtures/validation_artifact_freshness"
GENERATED_AT = "2026-05-08T05:30:00Z"
CURRENT_HEAD = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def run_receipt_output(
    artifact: str,
    dirty_paths: str = "clean_dirty_paths.json",
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--artifact",
            f"{FIXTURES_REL}/{artifact}",
            "--dirty-paths-json",
            f"{FIXTURES_REL}/{dirty_paths}",
            "--current-head",
            CURRENT_HEAD,
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


def run_receipt(artifact: str, dirty_paths: str = "clean_dirty_paths.json") -> dict:
    output = run_receipt_output(artifact, dirty_paths)
    return json.loads(output.stdout)


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def load_script_module():
    spec = importlib.util.spec_from_file_location("validation_artifact_freshness", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ValidationArtifactFreshnessContract(unittest.TestCase):
    def assert_output_matches_golden(
        self,
        output: subprocess.CompletedProcess[str],
        fixture_name: str,
    ) -> None:
        expected = fixture_text(fixture_name)
        actual_json = json.loads(output.stdout)
        expected_json = json.loads(expected)

        self.assertEqual(actual_json, expected_json, "parsed receipt JSON must match")
        self.assertEqual(output.stdout, expected)

    def test_current_artifact_output_matches_full_reviewed_golden(self) -> None:
        output = run_receipt_output("current_artifact.json")
        self.assert_output_matches_golden(output, "current_artifact_expected.json")

    def test_stale_head_output_matches_full_reviewed_golden(self) -> None:
        output = run_receipt_output("stale_head_artifact.json")
        self.assert_output_matches_golden(output, "stale_head_artifact_expected.json")

    def test_current_artifact_is_citable_for_touched_surface(self) -> None:
        receipt = run_receipt("current_artifact.json")

        self.assertEqual(receipt["schema_version"], "validation-artifact-freshness-v1")
        self.assertEqual(receipt["generated_at"], GENERATED_AT)
        self.assertEqual(receipt["current_date"], "2026-05-08")
        self.assertEqual(receipt["classification"], "current")
        self.assertEqual(receipt["verdict"], "current")
        self.assertTrue(receipt["markers"]["head_matches"])
        self.assertEqual(receipt["artifact"]["touched_files"], ["scripts/proof_runner.py"])

    def test_superseded_head_marks_artifact_stale(self) -> None:
        receipt = run_receipt("stale_head_artifact.json")

        self.assertEqual(receipt["classification"], "stale-head")
        self.assertEqual(receipt["verdict"], "stale")
        self.assertFalse(receipt["markers"]["head_matches"])
        self.assertIn("superseded HEAD", receipt["remediation"]["summary"])
        self.assertIn("Do not cite", receipt["remediation"]["operator_note"])

    def test_dirty_overlap_marks_artifact_stale(self) -> None:
        receipt = run_receipt("current_artifact.json", "dirty_touched_overlap.json")

        self.assertEqual(receipt["classification"], "stale-dirty-overlap")
        self.assertEqual(receipt["verdict"], "stale")
        self.assertEqual(receipt["markers"]["dirty_touched_overlap"], ["scripts/proof_runner.py"])
        self.assertIn("overlap", receipt["remediation"]["summary"])

    def test_dirty_overlap_output_matches_full_reviewed_golden(self) -> None:
        output = run_receipt_output("current_artifact.json", "dirty_touched_overlap.json")
        self.assert_output_matches_golden(output, "dirty_touched_overlap_expected.json")

    def test_peer_dirty_paths_are_external_blockers_not_artifact_staleness(self) -> None:
        receipt = run_receipt("current_artifact.json", "dirty_external_paths.json")

        self.assertEqual(receipt["classification"], "current-with-external-dirt")
        self.assertEqual(receipt["verdict"], "blocked-external")
        self.assertEqual(receipt["markers"]["dirty_touched_overlap"], [])
        self.assertEqual(receipt["markers"]["dirty_external_paths"], ["src/channel/mod.rs"])
        self.assertIn("unrelated dirty paths", receipt["remediation"]["operator_note"])

    def test_external_dirt_output_matches_full_reviewed_golden(self) -> None:
        output = run_receipt_output("current_artifact.json", "dirty_external_paths.json")
        self.assert_output_matches_golden(output, "dirty_external_paths_expected.json")

    def test_git_status_arrow_is_split_only_for_rename_or_copy_rows(self) -> None:
        module = load_script_module()

        paths = module.parse_status_lines(
            [
                " M tests/fixtures/a -> b.log",
                "R  old/name.log -> new/name.log",
                "C  source.log -> copy.log",
            ]
        )

        self.assertEqual(
            paths,
            [
                "tests/fixtures/a -> b.log",
                "new/name.log",
                "copy.log",
            ],
        )

    def test_missing_head_invalidates_artifact(self) -> None:
        receipt = run_receipt("unbound_artifact.json")

        self.assertEqual(receipt["classification"], "unbound-artifact")
        self.assertEqual(receipt["verdict"], "invalid")
        self.assertFalse(receipt["markers"]["has_artifact_head"])
        self.assertIn("repo HEAD", receipt["remediation"]["summary"])

    def test_unbound_artifact_output_matches_full_reviewed_golden(self) -> None:
        output = run_receipt_output("unbound_artifact.json")
        self.assert_output_matches_golden(output, "unbound_artifact_expected.json")

    def test_nested_validation_frontier_record_is_supported(self) -> None:
        receipt = run_receipt("nested_validation_frontier_artifact.json")

        self.assertEqual(receipt["classification"], "current")
        self.assertEqual(receipt["artifact"]["decision"], "pass")
        self.assertEqual(
            receipt["artifact"]["touched_files"],
            ["tests/rch_retrieval_receipt_contract.rs"],
        )

    def test_nested_validation_frontier_output_matches_full_reviewed_golden(self) -> None:
        output = run_receipt_output("nested_validation_frontier_artifact.json")
        self.assert_output_matches_golden(
            output,
            "nested_validation_frontier_artifact_expected.json",
        )

    def test_helper_declares_it_does_not_mutate_project_state(self) -> None:
        receipt = run_receipt("current_artifact.json")

        self.assertTrue(receipt["non_mutating"])
        for key in (
            "runs_cargo",
            "runs_git_mutation",
            "runs_beads_mutation",
            "runs_destructive_command",
        ):
            self.assertFalse(receipt["forbidden_actions"][key], key)


if __name__ == "__main__":
    unittest.main(verbosity=2)
