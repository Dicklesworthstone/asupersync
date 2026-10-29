#!/usr/bin/env python3
"""Exercise release source selection with real Git objects, without Cargo/network.

Run: python3 -m unittest discover -s scripts/ci -p test_release_source.py -v
Scratch repositories are retained under the system temp directory for diagnosis.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("release_source.py").resolve()
SPEC = importlib.util.spec_from_file_location("release_source", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
source = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source)


class ReleaseSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(tempfile.mkdtemp(prefix="release-source-test-"))
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Release Source Test")
        self.git("config", "user.email", "release-source@example.invalid")
        self.write_source("0.6.0", "nightly-2026-08-31")
        self.commit("candidate")
        self.candidate = self.git("rev-parse", "HEAD").strip()
        self.git("tag", "v0.6.0")

    def git(self, *args: str) -> str:
        result = subprocess.run(["git", "-C", str(self.repo), *args],
                                capture_output=True, text=True, check=True)
        return result.stdout

    def write_source(self, version: str, channel: str, *, heading: str | None = None) -> None:
        (self.repo / "Cargo.toml").write_text(
            f'[package]\nname = "asupersync"\nversion = "{version}"\n', encoding="utf-8")
        (self.repo / "rust-toolchain.toml").write_text(
            f'[toolchain]\nchannel = "{channel}"\n', encoding="utf-8")
        (self.repo / "CHANGELOG.md").write_text(
            heading if heading is not None else f"## [{version}] - 2026-10-28\n",
            encoding="utf-8")

    def commit(self, message: str) -> None:
        self.git("add", "Cargo.toml", "rust-toolchain.toml", "CHANGELOG.md")
        self.git("commit", "-m", message)

    def cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(SCRIPT), "--repo", str(self.repo), *args],
                              capture_output=True, text=True, check=False)

    def test_lightweight_tag_is_resolved_to_full_commit(self) -> None:
        self.assertEqual(source.resolve(self.repo, "v0.6.0"), {
            "tag": "v0.6.0", "version": "0.6.0", "prerelease": "false",
            "source_sha": self.candidate, "rust_toolchain": "nightly-2026-08-31",
        })

    def test_dispatch_head_does_not_supply_manifest_or_compiler(self) -> None:
        self.write_source("0.7.0", "nightly-2026-10-01")
        self.commit("main advanced after release tag")
        selected = source.resolve(self.repo, "v0.6.0")
        self.assertEqual(selected["source_sha"], self.candidate)
        self.assertEqual(selected["version"], "0.6.0")
        self.assertEqual(selected["rust_toolchain"], "nightly-2026-08-31")
        with self.assertRaisesRegex(source.ReleaseSourceError, "checkout HEAD"):
            source.resolve(self.repo, "v0.6.0", expected_sha=self.candidate)

    def test_same_version_different_source_is_not_qualified(self) -> None:
        self.write_source("0.6.0", "nightly-2026-10-01")
        self.commit("different source with unchanged version")
        with self.assertRaisesRegex(source.ReleaseSourceError, "checkout HEAD"):
            source.resolve(self.repo, "v0.6.0", expected_sha=self.candidate)

    def test_annotated_prerelease_tag_is_peeled(self) -> None:
        self.write_source("0.6.1-rc.1", "nightly-2026-08-31")
        self.commit("prerelease")
        self.git("tag", "-a", "v0.6.1-rc.1", "-m", "release candidate")
        selected = source.resolve(self.repo, "v0.6.1-rc.1")
        self.assertEqual(selected["source_sha"], self.git("rev-parse", "HEAD").strip())
        self.assertNotEqual(selected["source_sha"], self.git("rev-parse", "v0.6.1-rc.1").strip())
        self.assertEqual(selected["prerelease"], "true")

    def test_missing_tag_is_not_created_or_inferred_from_head(self) -> None:
        with self.assertRaises(source.ReleaseSourceError):
            source.resolve(self.repo, "v0.7.0")
        self.assertEqual(self.git("tag", "--list"), "v0.6.0\n")

    def test_mismatched_tag_version_fails_even_when_head_version_matches(self) -> None:
        self.git("tag", "v0.7.0")
        self.write_source("0.7.0", "nightly-2026-08-31")
        self.commit("head version matches requested tag, tagged version does not")
        with self.assertRaisesRegex(source.ReleaseSourceError, "tag version"):
            source.resolve(self.repo, "v0.7.0")

    def test_moved_tag_fails_against_planned_sha(self) -> None:
        self.write_source("0.6.0", "nightly-2026-10-01")
        self.commit("replacement candidate")
        self.git("tag", "--force", "v0.6.0")  # Test repository only.
        with self.assertRaisesRegex(source.ReleaseSourceError, "tag moved"):
            source.resolve(self.repo, "v0.6.0", expected_sha=self.candidate)

    def test_clean_planned_checkout_is_accepted(self) -> None:
        selected = source.resolve(self.repo, "v0.6.0", expected_sha=self.candidate)
        self.assertEqual(selected["source_sha"], self.candidate)

    def test_tracked_worktree_changes_are_refused(self) -> None:
        self.write_source("0.6.1", "nightly-2026-08-31")
        with self.assertRaisesRegex(source.ReleaseSourceError, "tracked modifications"):
            source.resolve(self.repo, "v0.6.0", expected_sha=self.candidate)

    def test_staged_changes_are_refused(self) -> None:
        self.write_source("0.6.1", "nightly-2026-08-31")
        self.git("add", "Cargo.toml")
        with self.assertRaisesRegex(source.ReleaseSourceError, "tracked modifications"):
            source.resolve(self.repo, "v0.6.0", expected_sha=self.candidate)

    def test_changelog_must_come_from_tag_and_match_exact_version(self) -> None:
        self.write_source("0.6.1", "nightly-2026-08-31", heading="## [0.6.10] - 2026-10-28\n")
        self.commit("missing release entry")
        self.git("tag", "v0.6.1")
        self.write_source("0.6.1", "nightly-2026-08-31")
        self.commit("main entry is not release evidence")
        with self.assertRaisesRegex(source.ReleaseSourceError, "tagged CHANGELOG"):
            source.resolve(self.repo, "v0.6.1")
        selected = source.resolve(self.repo, "v0.6.1", allow_missing_changelog=True)
        self.assertEqual(selected["source_sha"], self.git("rev-parse", "v0.6.1").strip())

    def test_changelog_waiver_does_not_waive_identity(self) -> None:
        self.git("tag", "v0.7.0")
        with self.assertRaisesRegex(source.ReleaseSourceError, "tag version"):
            source.resolve(self.repo, "v0.7.0", allow_missing_changelog=True)

    def test_floating_and_invalid_toolchain_pins_are_refused(self) -> None:
        for index, pin in enumerate(["nightly", "stable", "nightly-2026-02-30", "nightly-2026-8-31"]):
            version = f"0.7.{index}"
            self.write_source(version, pin)
            self.commit(f"bad compiler {index}")
            self.git("tag", f"v{version}")
            with self.subTest(pin=pin), self.assertRaises(source.ReleaseSourceError):
                source.resolve(self.repo, f"v{version}")

    def test_invalid_tag_input_cannot_write_outputs_or_execute_shell(self) -> None:
        output = self.repo / "outputs"
        for tag in ["main", "0.6.0", "v00.6.0", "v0.6.0-01", "v0.6.0\nsource_sha=evil",
                    'v0.6.0$(touch INJECTED)', 'v0.6.0"; touch INJECTED; #']:
            with self.subTest(tag=tag):
                result = self.cli("--tag", tag, "--github-output", str(output))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())
                self.assertFalse((self.repo / "INJECTED").exists())

    def test_cli_outputs_are_emitted_only_after_validation(self) -> None:
        output = self.repo / "outputs"
        result = self.cli("--tag", "v0.6.0", "--verify-head", self.candidate,
                          "--github-output", str(output))
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        self.assertEqual(values, data)
        self.assertEqual(values["source_sha"], self.candidate)

    def test_tag_pointing_to_blob_is_not_a_release(self) -> None:
        blob = self.git("rev-parse", "HEAD:Cargo.toml").strip()
        self.git("tag", "v0.8.0", blob)
        with self.assertRaises(source.ReleaseSourceError):
            source.resolve(self.repo, "v0.8.0")

    def test_git_replace_cannot_change_tagged_manifest(self) -> None:
        self.write_source("0.7.0", "nightly-2026-10-01")
        self.commit("replacement tree")
        replacement = self.git("rev-parse", "HEAD").strip()
        self.git("replace", self.candidate, replacement)
        selected = source.resolve(self.repo, "v0.6.0")
        self.assertEqual(selected["version"], "0.6.0")
        self.assertEqual(selected["source_sha"], self.candidate)


if __name__ == "__main__":
    unittest.main()
