#!/usr/bin/env python3
"""
Agent-swarm safe proof runner with reservation awareness.

This script provides preflight checks before expensive validation commands,
ensuring they won't fail due to unrelated dirty surfaces or reservation conflicts.
Compatible with the validation frontier ledger schema.
"""

import argparse
import fnmatch
import json
import subprocess
import sys
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any


class ProofLaneManifest:
    """Wrapper for the proof lane manifest."""

    def __init__(self, manifest_path: str = "artifacts/proof_lane_manifest_v1.json"):
        self.path = Path(manifest_path)
        with open(self.path) as f:
            self.data = json.load(f)

    def get_lane(self, lane_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific lane by ID."""
        for lane in self.data["lanes"]:
            if lane["lane_id"] == lane_id:
                return lane
        return None

    def list_lane_ids(self) -> List[str]:
        """List all available lane IDs."""
        return [lane["lane_id"] for lane in self.data["lanes"]]


class ValidationFrontierRecord:
    """Builder for validation frontier ledger records."""

    def __init__(self, command: str, touched_files: List[str]):
        self.command = command
        self.timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        self.touched_files = touched_files
        self.decision = "pass"
        self.error_class = ""
        self.first_failure = {
            "crate_or_surface": "",
            "target": "",
            "file": "",
            "line": 0
        }
        self.likely_owner = ""
        self.likely_bead = None
        self.supplemental_proof_command = ""
        self.summary = ""

    def as_blocked_external(
        self,
        error_class: str,
        file: str,
        summary: str,
        owner: str = "shared-main external blocker",
        supplemental: str = "",
        line: int = 0
    ) -> Dict[str, Any]:
        """Mark as externally blocked."""
        return {
            "command": self.command,
            "timestamp": self.timestamp,
            "touched_files": self.touched_files,
            "decision": "blocked-external",
            "error_class": error_class,
            "first_failure": {
                "crate_or_surface": "coordination",
                "target": "preflight",
                "file": file,
                "line": line
            },
            "likely_owner": owner,
            "likely_bead": self.likely_bead,
            "supplemental_proof_command": supplemental,
            "summary": summary
        }

    def as_pass(self, supplemental: str = "") -> Dict[str, Any]:
        """Mark as passed."""
        return {
            "command": self.command,
            "timestamp": self.timestamp,
            "touched_files": self.touched_files,
            "decision": "pass",
            "error_class": "",
            "first_failure": {
                "crate_or_surface": "",
                "target": "",
                "file": "",
                "line": 0
            },
            "likely_owner": "local_change",
            "likely_bead": self.likely_bead,
            "supplemental_proof_command": supplemental,
            "summary": "preflight checks passed"
        }


class GitStatus:
    """Git working tree analysis."""

    def __init__(self, repo_root: str = "."):
        self.repo_root = Path(repo_root)
        self._status_lines = None

    def _get_status(self) -> List[str]:
        """Get git status --short output."""
        if self._status_lines is None:
            try:
                result = subprocess.run(
                    ["git", "status", "--short"],
                    capture_output=True,
                    text=True,
                    cwd=self.repo_root,
                    check=True
                )
                self._status_lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            except subprocess.CalledProcessError:
                self._status_lines = []
        return self._status_lines

    def has_uncommitted_changes(self) -> bool:
        """Check if there are uncommitted changes."""
        return len(self._get_status()) > 0

    def get_uncommitted_files(self) -> List[str]:
        """Get list of uncommitted files."""
        files = []
        for line in self._get_status():
            if len(line) >= 3:
                # Git status format: XY filename
                files.append(line[3:])
        return files

    def get_staged_files(self) -> List[str]:
        """Get list of staged files."""
        staged = []
        for line in self._get_status():
            if len(line) >= 3 and line[0] != ' ' and line[0] != '?':
                staged.append(line[3:])
        return staged


class AgentMailChecker:
    """Agent Mail reservation checker."""

    def __init__(
        self,
        project_key: str,
        agent_name: str = "unknown",
        reservation_snapshot: Optional[str] = None
    ):
        self.project_key = project_key
        self.agent_name = agent_name
        self.reservation_snapshot = Path(reservation_snapshot) if reservation_snapshot else None
        self.last_check = {
            "source": "not_configured",
            "classifications": []
        }

    def check_file_reservations(self, file_paths: List[str]) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Check if any files have active reservations.
        Returns (has_conflicts, conflicts_list).
        """
        if not self.reservation_snapshot:
            self.last_check = {
                "source": "not_configured",
                "classifications": []
            }
            return False, []

        try:
            snapshot = json.loads(self.reservation_snapshot.read_text())
        except Exception as error:
            conflict = {
                "path": str(self.reservation_snapshot),
                "path_pattern": str(self.reservation_snapshot),
                "classification": "unavailable",
                "summary": f"reservation snapshot unavailable: {error}"
            }
            self.last_check = {
                "source": "snapshot",
                "classifications": [conflict]
            }
            return True, [conflict]

        reservations = self._extract_reservations(snapshot)
        classifications = [
            self._classify_reservation(reservation, file_paths)
            for reservation in reservations
        ]
        classifications = [item for item in classifications if item is not None]
        conflicts = [
            item for item in classifications
            if item["classification"] in {"peer-active", "tracker-only", "unknown-owner", "unavailable"}
        ]
        self.last_check = {
            "source": "snapshot",
            "classifications": classifications
        }
        return bool(conflicts), conflicts

    def _extract_reservations(self, snapshot: Any) -> List[Dict[str, Any]]:
        """Extract reservation rows from known snapshot shapes."""
        if isinstance(snapshot, list):
            return [item for item in snapshot if isinstance(item, dict)]
        if not isinstance(snapshot, dict):
            return []
        for key in ("reservations", "active_reservations", "granted"):
            rows = snapshot.get(key)
            if isinstance(rows, list):
                return [item for item in rows if isinstance(item, dict)]
        return []

    def _classify_reservation(
        self,
        reservation: Dict[str, Any],
        file_paths: List[str]
    ) -> Optional[Dict[str, Any]]:
        pattern = (
            reservation.get("path_pattern")
            or reservation.get("path")
            or reservation.get("pattern")
            or reservation.get("glob")
        )
        if not pattern:
            return None

        touched_file = self._first_matching_file(str(pattern), file_paths)
        if not touched_file:
            return None

        holder = (
            reservation.get("agent_name")
            or reservation.get("holder")
            or reservation.get("owner")
            or reservation.get("agent")
        )
        expires_ts = reservation.get("expires_ts") or reservation.get("expires_at") or ""
        released_ts = reservation.get("released_ts") or reservation.get("released_at")

        if released_ts or self._is_expired(expires_ts):
            classification = "expired"
        elif not holder:
            classification = "unknown-owner"
        elif holder == self.agent_name:
            classification = "owned-active"
        elif self._is_tracker_path(touched_file) or self._is_tracker_path(str(pattern)):
            classification = "tracker-only"
        else:
            classification = "peer-active"

        return {
            "path": touched_file,
            "path_pattern": str(pattern),
            "holder": holder or "",
            "expires_ts": expires_ts,
            "classification": classification,
            "summary": self._summary(classification, str(pattern), touched_file, holder, expires_ts)
        }

    def _first_matching_file(self, pattern: str, file_paths: List[str]) -> Optional[str]:
        normalized_pattern = pattern.removeprefix("./")
        for file_path in file_paths:
            normalized_file = file_path.removeprefix("./")
            if (
                normalized_file == normalized_pattern
                or fnmatch.fnmatchcase(normalized_file, normalized_pattern)
                or fnmatch.fnmatchcase(normalized_pattern, normalized_file)
            ):
                return normalized_file
        return None

    def _is_expired(self, expires_ts: Any) -> bool:
        if not expires_ts:
            return False
        try:
            timestamp = str(expires_ts).replace("Z", "+00:00")
            expires_at = datetime.fromisoformat(timestamp)
        except ValueError:
            return False
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return expires_at <= datetime.now(timezone.utc)

    def _is_tracker_path(self, path: str) -> bool:
        return path in {".beads/issues.jsonl", ".beads/beads.db"} or path.startswith(".beads/")

    def _summary(
        self,
        classification: str,
        pattern: str,
        touched_file: str,
        holder: Optional[str],
        expires_ts: Any
    ) -> str:
        if classification == "owned-active":
            return f"owned-active reservation covers {touched_file}"
        if classification == "expired":
            return f"expired reservation for {pattern} no longer blocks {touched_file}"
        if classification == "unknown-owner":
            return f"unknown-owner reservation blocks {touched_file}"
        if classification == "tracker-only":
            return f"tracker-only reservation held by {holder} blocks {touched_file} until {expires_ts}"
        if classification == "peer-active":
            return f"peer-active reservation held by {holder} blocks {touched_file} until {expires_ts}"
        return f"{classification} reservation for {pattern} affects {touched_file}"


class ProofRunner:
    """Main proof runner logic."""

    def __init__(
        self,
        repo_root: str = ".",
        agent_name: str = "unknown",
        reservation_snapshot: Optional[str] = None,
        skip_dirty_check: bool = False
    ):
        self.repo_root = Path(repo_root).resolve()
        self.manifest = ProofLaneManifest()
        self.git = GitStatus(repo_root)
        self.agent_mail = AgentMailChecker(str(self.repo_root), agent_name, reservation_snapshot)
        self.skip_dirty_check = skip_dirty_check

    def analyze_preflight(
        self,
        lane_id: str,
        touched_files: List[str]
    ) -> Tuple[bool, ValidationFrontierRecord]:
        """
        Analyze preflight conditions for a proof lane.
        Returns (can_proceed, frontier_record).
        """
        lane = self.manifest.get_lane(lane_id)
        if not lane:
            record = ValidationFrontierRecord(f"proof-runner --lane={lane_id}", touched_files)
            return False, record.as_blocked_external(
                "unknown_proof_lane",
                "artifacts/proof_lane_manifest_v1.json",
                f"unknown lane {lane_id}",
                supplemental="br ready --json"
            )

        command = lane["command"]
        record = ValidationFrontierRecord(command, touched_files)

        # Check file reservations before dirty state so explicit peer locks win.
        has_conflicts, conflicts = self.agent_mail.check_file_reservations(touched_files)
        if has_conflicts and conflicts:
            conflict = conflicts[0]
            supplemental = self._generate_narrow_proof(touched_files, lane)
            return False, record.as_blocked_external(
                "file_reservation_conflict",
                conflict.get("path", "unknown"),
                f"reservation conflict ({conflict.get('classification', 'unknown')}): {conflict.get('summary', 'unknown')}",
                supplemental=supplemental
            )

        # Check for uncommitted changes
        if not self.skip_dirty_check:
            uncommitted = self.git.get_uncommitted_files()
            if uncommitted:
                unrelated_files = [f for f in uncommitted if f not in touched_files]
                if unrelated_files:
                    # Has unrelated dirty files - suggest narrow proof
                    supplemental = self._generate_narrow_proof(touched_files, lane)
                    return False, record.as_blocked_external(
                        "peer_dirty_index_conflict",
                        unrelated_files[0],
                        f"unrelated dirty files present: {', '.join(unrelated_files[:3])}",
                        supplemental=supplemental
                    )

        # Check for staged changes from other agents
        if not self.skip_dirty_check:
            staged = self.git.get_staged_files()
            if staged:
                unrelated_staged = [f for f in staged if f not in touched_files]
                if unrelated_staged:
                    supplemental = self._generate_narrow_proof(touched_files, lane)
                    return False, record.as_blocked_external(
                        "peer_dirty_index_conflict",
                        unrelated_staged[0],
                        f"unrelated staged paths present: {', '.join(unrelated_staged[:3])}",
                        supplemental=supplemental
                    )

        # All checks passed
        supplemental = self._generate_narrow_proof(touched_files, lane)
        return True, record.as_pass(supplemental=supplemental)

    def _generate_narrow_proof(self, touched_files: List[str], lane: Dict[str, Any]) -> str:
        """Generate a narrow supplemental proof command."""
        lane_kind = lane.get("kind", "unknown")

        if lane_kind == "format_frontier":
            # For formatting, check only the touched files
            if len(touched_files) == 1:
                return f"rch exec -- rustfmt --edition 2024 --check {touched_files[0]}"
            else:
                return f"rch exec -- rustfmt --edition 2024 --check {' '.join(touched_files[:5])}"

        elif lane_kind in ["compile_frontier", "test_frontier"]:
            # For compilation/tests, try to narrow to specific targets
            rust_files = [f for f in touched_files if f.endswith('.rs')]
            if rust_files:
                # If we have specific test files, run just those
                if any('test' in f for f in rust_files):
                    test_files = [f for f in rust_files if 'test' in f]
                    if test_files:
                        test_name = Path(test_files[0]).stem
                        return f"rch exec -- cargo test {test_name} -- --nocapture"

                # Otherwise, try library check
                return "rch exec -- cargo check --lib"

        elif lane_kind == "lint_frontier":
            # For linting, check only specific files if possible
            rust_files = [f for f in touched_files if f.endswith('.rs')]
            if rust_files and len(rust_files) <= 3:
                return f"rch exec -- cargo clippy --lib -- -D warnings"

        # Fallback: basic format check
        return f"rch exec -- rustfmt --edition 2024 --check {' '.join(touched_files[:3])}"

    def run_preflight(
        self,
        lane_id: str,
        touched_files: List[str],
        output_format: str = "json"
    ) -> Dict[str, Any]:
        """Run preflight analysis and return results."""
        can_proceed, record = self.analyze_preflight(lane_id, touched_files)

        result = {
            "preflight_passed": can_proceed,
            "lane_id": lane_id,
            "command_would_run": self.manifest.get_lane(lane_id)["command"] if self.manifest.get_lane(lane_id) else "",
            "reservation_check": self.agent_mail.last_check,
            "validation_frontier_record": record,
            "recommendation": "proceed" if can_proceed else "use_supplemental"
        }

        return result

    def suggest_lanes_for_changes(self, touched_files: List[str]) -> List[str]:
        """Suggest appropriate proof lanes based on touched files."""
        suggestions = []

        # Always suggest formatting check
        suggestions.append("rustfmt-check")

        # If Rust files were touched, suggest compilation and linting
        rust_files = [f for f in touched_files if f.endswith('.rs')]
        if rust_files:
            suggestions.append("all-targets-check")
            suggestions.append("clippy-all-targets")

            # If it's library code, suggest lib tests
            lib_files = [f for f in rust_files if f.startswith('src/') and not f.startswith('tests/')]
            if lib_files:
                suggestions.append("lib-tests")

        # If Cargo.toml was touched, suggest dependency checks
        if any('Cargo.toml' in f for f in touched_files):
            suggestions.append("default-production-tokio-tree")

        # If docs were touched, suggest doc build
        doc_files = [f for f in touched_files if any(word in f.lower() for word in ['readme', 'doc', '.md'])]
        if doc_files:
            suggestions.append("rustdoc-api")

        return suggestions


def main():
    parser = argparse.ArgumentParser(
        description="Agent-swarm safe proof runner with reservation awareness"
    )
    parser.add_argument(
        "--lane",
        help="Proof lane ID from the manifest"
    )
    parser.add_argument(
        "--touched-files",
        nargs="+",
        default=[],
        help="Files that motivated this validation attempt"
    )
    parser.add_argument(
        "--output",
        choices=["json", "human"],
        default="json",
        help="Output format"
    )
    parser.add_argument(
        "--list-lanes",
        action="store_true",
        help="List available proof lanes"
    )
    parser.add_argument(
        "--suggest-lanes",
        action="store_true",
        help="Suggest lanes for the touched files"
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually execute the proof command if preflight passes"
    )
    parser.add_argument(
        "--agent-name",
        default=os.environ.get("AGENT_NAME", "unknown"),
        help="Agent name used to distinguish owned reservations"
    )
    parser.add_argument(
        "--reservation-snapshot",
        help="JSON snapshot of Agent Mail file reservations for fixture-backed checks"
    )
    parser.add_argument(
        "--skip-dirty-check",
        action="store_true",
        help="Skip git dirty-state checks; intended for reservation classifier fixtures"
    )

    args = parser.parse_args()

    try:
        runner = ProofRunner(
            agent_name=args.agent_name,
            reservation_snapshot=args.reservation_snapshot,
            skip_dirty_check=args.skip_dirty_check
        )

        if args.list_lanes:
            lanes = runner.manifest.list_lane_ids()
            if args.output == "json":
                print(json.dumps({"available_lanes": lanes}, indent=2))
            else:
                print("Available proof lanes:")
                for lane in lanes:
                    print(f"  {lane}")
            return 0

        if args.suggest_lanes:
            suggestions = runner.suggest_lanes_for_changes(args.touched_files)
            if args.output == "json":
                print(json.dumps({"suggested_lanes": suggestions, "touched_files": args.touched_files}, indent=2))
            else:
                print(f"Suggested lanes for {args.touched_files}:")
                for lane in suggestions:
                    print(f"  {lane}")
            return 0

        # Validate required arguments for proof analysis
        if not args.lane:
            parser.error("--lane is required when not using --list-lanes or --suggest-lanes")

        # Run preflight analysis
        result = runner.run_preflight(args.lane, args.touched_files, args.output)

        if args.output == "json":
            print(json.dumps(result, indent=2))
        else:
            if result["preflight_passed"]:
                print(f"✅ Preflight PASSED for lane {args.lane}")
                print(f"Command: {result['command_would_run']}")
                if args.execute:
                    print("Executing...")
                    # Execute the command
                    lane = runner.manifest.get_lane(args.lane)
                    if lane:
                        cmd = lane["command"]
                        return subprocess.call(cmd, shell=True)
            else:
                record = result["validation_frontier_record"]
                print(f"❌ Preflight BLOCKED for lane {args.lane}")
                print(f"Reason: {record['summary']}")
                print(f"Blocker file: {record['first_failure']['file']}")
                print(f"Suggested supplemental proof: {record['supplemental_proof_command']}")
                return 1

        return 0 if result["preflight_passed"] else 1

    except Exception as e:
        if args.output == "json":
            print(json.dumps({"error": str(e)}, indent=2))
        else:
            print(f"Error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
