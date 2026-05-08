#!/usr/bin/env python3
"""Incident forensics playbook contract checker (asupersync-umelq.12.5).

Validates that incident-forensics operator docs and testing references stay in
sync with executable drill commands and artifact contracts.

Outputs:
  - artifacts/incident_forensics_playbook_check_report.json
  - artifacts/incident_forensics_playbook_check_events.ndjson
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Clause:
    clause_id: str
    file_path: str
    pattern: str
    description: str


def _git_sha(project_root: pathlib.Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception:
        return None
    sha = result.stdout.strip()
    return sha or None


def _check_clause(project_root: pathlib.Path, clause: Clause) -> dict[str, Any]:
    target = project_root / clause.file_path
    status = "pass"
    detail = "clause satisfied"

    if not target.exists():
        status = "fail"
        detail = f"file not found: {clause.file_path}"
        return {
            "clause_id": clause.clause_id,
            "file": clause.file_path,
            "description": clause.description,
            "status": status,
            "detail": detail,
        }

    text = target.read_text(encoding="utf-8")
    if re.search(clause.pattern, text, re.MULTILINE) is None:
        status = "fail"
        detail = f"missing required pattern: {clause.pattern}"

    return {
        "clause_id": clause.clause_id,
        "file": clause.file_path,
        "description": clause.description,
        "status": status,
        "detail": detail,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        default=".",
        help="Project root directory (default: current directory)",
    )
    parser.add_argument(
        "--report-path",
        default="artifacts/incident_forensics_playbook_check_report.json",
        help="Output JSON report path",
    )
    parser.add_argument(
        "--events-path",
        default="artifacts/incident_forensics_playbook_check_events.ndjson",
        help="Output NDJSON events path",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    project_root = pathlib.Path(args.project_root).resolve()

    clauses = [
        Clause(
            "IFP-001",
            "docs/replay-debugging.md",
            r"^## WASM Incident Forensics Playbook \(asupersync-umelq\.12\.5\)",
            "Replay guide must include dedicated incident-forensics playbook section.",
        ),
        Clause(
            "IFP-002",
            "docs/replay-debugging.md",
            r"bash \./scripts/test_wasm_incident_forensics_e2e\.sh",
            "Replay guide must publish canonical deterministic drill command.",
        ),
        Clause(
            "IFP-003",
            "docs/replay-debugging.md",
            (
                r"rch exec -- env\b[^\n]*\b"
                r"CARGO_TARGET_DIR=\$\{TMPDIR:-/tmp\}/rch_target_replay_debugging_docs\b"
                r"[^\n]*\bcargo run --quiet --features cli --bin asupersync --"
            ),
            "Replay guide must include explicit rch-offloaded replay command template "
            "with a scoped cargo target directory.",
        ),
        Clause(
            "IFP-004",
            "docs/integration.md",
            r"Incident forensics playbook \(asupersync-umelq\.12\.5\)",
            "Integration guide must link incident triage flow to playbook contract.",
        ),
        Clause(
            "IFP-005",
            "TESTING.md",
            r"check_incident_forensics_playbook\.py",
            "Testing guide must include playbook contract checker command.",
        ),
        Clause(
            "IFP-006",
            "TESTING.md",
            r"run_all_e2e\.sh --suite wasm-incident-forensics",
            "Testing guide must include incident-forensics E2E drill suite command.",
        ),
        Clause(
            "IFP-007",
            "TESTING.md",
            r"target/e2e-results/wasm_incident_forensics",
            "Testing guide must document deterministic artifact root for drill outputs.",
        ),
    ]

    checks = [_check_clause(project_root, clause) for clause in clauses]
    fail_count = sum(1 for check in checks if check["status"] == "fail")
    pass_count = sum(1 for check in checks if check["status"] == "pass")
    gate_status = "pass" if fail_count == 0 else "fail"

    generated_at = dt.datetime.now(dt.timezone.utc).isoformat()
    report = {
        "schema_version": "incident-forensics-playbook-check-v1",
        "generated_at_utc": generated_at,
        "git_sha": _git_sha(project_root),
        "gate_status": gate_status,
        "summary": {
            "total": len(checks),
            "passed": pass_count,
            "failed": fail_count,
        },
        "checks": checks,
    }

    report_path = project_root / args.report_path
    events_path = project_root / args.events_path
    report_path.parent.mkdir(parents=True, exist_ok=True)
    events_path.parent.mkdir(parents=True, exist_ok=True)

    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with events_path.open("w", encoding="utf-8") as handle:
        for check in checks:
            event = {
                "schema_version": "incident-forensics-playbook-event-v1",
                "generated_at_utc": generated_at,
                "clause_id": check["clause_id"],
                "status": check["status"],
                "file": check["file"],
                "detail": check["detail"],
            }
            handle.write(json.dumps(event, sort_keys=True) + "\n")

    print(json.dumps({
        "report": str(report_path),
        "events": str(events_path),
        "gate_status": gate_status,
        "failed": fail_count,
    }, sort_keys=True))

    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
