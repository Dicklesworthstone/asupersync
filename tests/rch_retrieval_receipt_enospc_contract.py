#!/usr/bin/env python3
"""ENOSPC contract for scripts/rch_retrieval_receipt.py."""

import json
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "rch_retrieval_receipt.py"
FIXTURE = "tests/fixtures/rch_retrieval_receipt/passed_after_retrieval_enospc.log"
GENERATED_AT = "2026-05-18T19:10:00Z"
COMMAND = (
    "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_maroontrout_semaphore_fuzz "
    "cargo check --manifest-path fuzz/Cargo.toml --bin semaphore_acquire_cancel"
)


def run_receipt() -> dict:
    completed = subprocess.run(
        [
            "python3",
            str(SCRIPT),
            "--log",
            FIXTURE,
            "--command",
            COMMAND,
            "--generated-at",
            GENERATED_AT,
            "--wrapper-exit-code",
            "1",
            "--artifact-free-proof-receipt",
            "--output",
            "json",
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(completed.stdout)


class RchRetrievalEnospcContract(unittest.TestCase):
    def test_remote_pass_and_local_enospc_are_split_verdicts(self) -> None:
        receipt = run_receipt()

        self.assertEqual(receipt["classification"], "passed_after_retrieval_enospc")
        self.assertEqual(receipt["decision"], "pass-with-retrieval-blocker")
        self.assertTrue(receipt["non_mutating"])

        closeout = receipt["artifact_free_proof_receipt"]
        self.assertEqual(closeout["remote_command_result"]["status"], "pass")
        self.assertEqual(closeout["remote_command_result"]["exit_code"], 0)

        retrieval = closeout["artifact_retrieval_result"]
        self.assertEqual(retrieval["status"], "blocked")
        self.assertEqual(retrieval["blocker_kind"], "local-disk-full")
        self.assertGreater(retrieval["blocker_line"], 0)
        self.assertIn("No space left on device", retrieval["blocker_text"])

        disk = closeout["local_disk_pressure"]
        self.assertEqual(disk["status"], "critical")
        self.assertEqual(disk["signal"], "enospc")
        self.assertEqual(disk["evidence_line"], retrieval["blocker_line"])
        self.assertIn("No space left on device", disk["evidence_text"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
