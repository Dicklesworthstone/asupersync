#!/usr/bin/env python3
"""Enumerate ATP release proof gates and receipt inputs.

This helper is intentionally non-mutating. It gives ATP-NR13 one strict entry
point for the release-proof shape: stable gate ids, owner beads, commands,
budgets, expected artifacts, and receipt-producing inputs that downstream
dashboards can consume without reinterpreting private implementation details.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "atp-release-proof-aggregator-v1"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DASHBOARD_CONTRACT = REPO_ROOT / "artifacts" / "atp_completion_dashboard_contract_v1.json"
DEFAULT_PROOF_LANE_MANIFEST = REPO_ROOT / "artifacts" / "proof_lane_manifest_v1.json"
DEFAULT_AUTOTUNE_CORPUS = REPO_ROOT / "tests" / "fixtures" / "atp_autotune_replay_corpus" / "corpus.json"
DEFAULT_ISSUES = REPO_ROOT / ".beads" / "issues.jsonl"
AUTOTUNE_SOURCE = "src/atp/autotune.rs"
AUTOTUNE_DECISION_SCHEMA = "atp-autotune-decision-receipt-v1"
AUTOTUNE_APPLICATION_SCHEMA = "atp-autotune-application-receipt-v1"
CARGO_RE = re.compile(r"(?<![A-Za-z0-9_.-])cargo(?![A-Za-z0-9_.-])")
SAFE_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
DONE_STATUSES = {"closed", "completed", "done", "tombstone"}
IN_PROGRESS_STATUSES = {"in_progress", "started"}
BLOCKED_STATUSES = {"blocked"}

ATP_NR13_ARTIFACTS = [
    "scripts/atp_release_proof/enumerator.py",
    "tests/atp/release_proof/aggregator_harness.rs",
]

GATE_FAMILY_BY_ID = {
    "ATP-NR0": "dashboard",
    "ATP-NR1": "no_mock",
    "ATP-NR2": "unit",
    "ATP-NR3": "unit",
    "ATP-NR4": "lab",
    "ATP-NR5": "e2e",
    "ATP-NR6": "e2e",
    "ATP-NR7": "lab",
    "ATP-NR8": "security",
    "ATP-NR9": "e2e",
    "ATP-NR10": "e2e",
    "ATP-NR11": "cross_platform",
    "ATP-NR12": "e2e",
    "ATP-NR13": "release_proof",
    "ATP-NR14": "governance",
}

LEGACY_RELEASE_INPUTS = [
    {
        "input_id": "atp-security-byzantine-legacy-proof",
        "source_bead": "asupersync-9fnel7",
        "family": "security",
        "source_path": "tests/atp/security/byzantine_e2e.rs",
    },
    {
        "input_id": "atp-benchmark-no-regression-legacy-proof",
        "source_bead": "asupersync-m7hmrq",
        "family": "benchmark",
        "source_path": "scripts/atp_perf/workflow_acceptance_smoke.py",
    },
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--dashboard-contract", type=Path, default=DEFAULT_DASHBOARD_CONTRACT)
    parser.add_argument("--proof-lane-manifest", type=Path, default=DEFAULT_PROOF_LANE_MANIFEST)
    parser.add_argument("--autotune-corpus", type=Path, default=DEFAULT_AUTOTUNE_CORPUS)
    parser.add_argument("--issues", type=Path, default=DEFAULT_ISSUES)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--output", choices=["json", "summary"], default="summary")
    parser.add_argument(
        "--allow-red",
        action="store_true",
        help="Return exit code 0 even when release-blocking rows are present.",
    )
    return parser.parse_args()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_issues(path: Path) -> dict[str, dict[str, Any]]:
    issues: dict[str, dict[str, Any]] = {}
    if not path.exists():
        return issues
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        issue_id = row.get("id")
        if isinstance(issue_id, str):
            issues[issue_id] = row
    return issues


def normalize_issue_status(value: Any) -> str:
    status = str(value or "").strip().lower().replace("-", "_")
    if status in DONE_STATUSES:
        return "done"
    if status in IN_PROGRESS_STATUSES:
        return "in_progress"
    if status in BLOCKED_STATUSES:
        return "blocked"
    if not status:
        return "missing"
    return status


def repo_path(repo_root: Path, relative_path: str) -> Path:
    return Path(relative_path) if Path(relative_path).is_absolute() else repo_root / relative_path


def path_exists(repo_root: Path, relative_path: str) -> bool:
    return repo_path(repo_root, relative_path).exists()


def first_non_assignment(argv: list[str], start: int = 0) -> int:
    index = start
    while index < len(argv) and "=" in argv[index]:
        name, _value = argv[index].split("=", 1)
        if not SAFE_ENV_NAME_RE.fullmatch(name):
            break
        index += 1
    return index


def cargo_command_policy(command: str) -> dict[str, Any]:
    mentions_cargo = CARGO_RE.search(command) is not None
    if not mentions_cargo:
        return {
            "mentions_cargo": False,
            "routed_through_rch": True,
            "has_target_dir": True,
            "compliant": True,
        }

    try:
        argv = shlex.split(command)
    except ValueError as err:
        return {
            "mentions_cargo": True,
            "routed_through_rch": False,
            "has_target_dir": False,
            "compliant": False,
            "parse_error": str(err),
        }

    lowered = [arg.lower() for arg in argv]
    program_index = first_non_assignment(argv)
    routed = lowered[program_index:program_index + 3] == ["rch", "exec", "--"]
    has_target_dir = False
    cargo_after_rch = False

    if routed:
        command_index = program_index + 3
        if command_index < len(argv) and lowered[command_index] == "env":
            command_index += 1
            while command_index < len(argv) and "=" in argv[command_index]:
                name, _value = argv[command_index].split("=", 1)
                if name == "CARGO_TARGET_DIR":
                    has_target_dir = True
                command_index += 1
        cargo_after_rch = command_index < len(argv) and lowered[command_index] == "cargo"

    return {
        "mentions_cargo": True,
        "routed_through_rch": routed and cargo_after_rch,
        "has_target_dir": has_target_dir,
        "compliant": routed and cargo_after_rch and has_target_dir,
    }


def timeout_seconds(command: str) -> int:
    lowered = command.lower()
    if "cargo test" in lowered or "cargo clippy" in lowered:
        return 1800
    if "cargo check" in lowered or "cargo tree" in lowered:
        return 900
    if "check_no_mock_policy" in lowered:
        return 600
    if lowered.startswith("bash ") or ".sh" in lowered:
        return 1800
    if lowered.startswith("python3 "):
        return 300
    return 900


def issue(
    gate_id: str,
    kind: str,
    message: str,
    severity: str = "p0",
    release_blocking: bool = True,
) -> dict[str, Any]:
    return {
        "gate_id": gate_id,
        "kind": kind,
        "severity": severity,
        "release_blocking": release_blocking,
        "message": message,
    }


def enumerate_gate(
    gate: dict[str, Any],
    repo_root: Path,
    issues_by_id: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    gate_id = str(gate.get("gate_id", ""))
    bead_id = str(gate.get("bead_id", ""))
    command = str(gate.get("proof_command", ""))
    artifacts = [str(path) for path in gate.get("required_artifacts", [])]
    if gate_id == "ATP-NR13":
        artifacts = sorted(set([*artifacts, *ATP_NR13_ARTIFACTS]))

    missing_artifacts = [path for path in artifacts if not path_exists(repo_root, path)]
    command_policy = cargo_command_policy(command)
    tracker_row = issues_by_id.get(bead_id)
    tracker_status = normalize_issue_status(tracker_row.get("status") if tracker_row else None)
    issues: list[dict[str, Any]] = []
    if not gate_id:
        issues.append(issue("<missing>", "missing_gate_id", "release gate is missing stable gate_id"))
    if not bead_id:
        issues.append(issue(gate_id or "<missing>", "missing_owner_bead", "release gate is missing owner bead"))
    if not command:
        issues.append(issue(gate_id, "missing_command", "release gate is missing proof command"))
    if not command_policy["compliant"]:
        issues.append(issue(gate_id, "unsafe_cargo_command", "cargo proof command must route through rch with CARGO_TARGET_DIR"))
    if tracker_row is None:
        issues.append(issue(gate_id, "missing_tracker_bead", f"owner bead {bead_id} is missing from issues ledger"))
    elif tracker_status != "done":
        issues.append(issue(gate_id, "gate_not_closed", f"owner bead {bead_id} status is {tracker_status}"))
    for path in missing_artifacts:
        issues.append(issue(gate_id, "missing_expected_artifact", f"missing expected artifact {path}"))

    row = {
        "gate_id": gate_id,
        "title": str(gate.get("title", "")),
        "owner_bead": bead_id,
        "tracker_status": tracker_status,
        "family": GATE_FAMILY_BY_ID.get(gate_id, "unknown"),
        "command": command,
        "timeout_seconds": int(gate.get("timeout_seconds") or timeout_seconds(command)),
        "expected_artifacts": artifacts,
        "missing_artifacts": missing_artifacts,
        "skip_policy": str(gate.get("skip_policy") or "no implicit skip; explicit waiver required"),
        "release_blocking": True,
        "command_policy": command_policy,
        "status": "red" if issues else "enumerated",
    }
    return row, issues


def proof_lane_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    lanes = [lane for lane in manifest.get("lanes", []) if isinstance(lane, dict)]
    guarantee_ids = sorted(
        {
            str(guarantee_id)
            for lane in lanes
            for guarantee_id in lane.get("guarantee_ids", [])
            if isinstance(guarantee_id, str)
        }
    )
    return {
        "manifest_version": manifest.get("contract_version"),
        "lane_count": len(lanes),
        "lane_ids": [str(lane.get("lane_id", "")) for lane in lanes],
        "guarantee_ids": guarantee_ids,
    }


def autotune_schema_input(repo_root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    source_path = repo_path(repo_root, AUTOTUNE_SOURCE)
    schemas: list[str] = []
    if source_path.exists():
        source = source_path.read_text(encoding="utf-8")
        for schema in [AUTOTUNE_DECISION_SCHEMA, AUTOTUNE_APPLICATION_SCHEMA]:
            if schema in source:
                schemas.append(schema)

    issues: list[dict[str, Any]] = []
    if AUTOTUNE_DECISION_SCHEMA not in schemas:
        issues.append(issue("ATP-NR13", "missing_decision_receipt_schema", "nm2us1 decision receipt schema is not visible"))
    if AUTOTUNE_APPLICATION_SCHEMA not in schemas:
        issues.append(issue("ATP-NR13", "missing_application_receipt_schema", "nm2us1 application receipt schema is not visible"))

    return {
        "input_id": "atp-autotune-explainable-receipt-schema",
        "source_bead": "asupersync-nm2us1",
        "family": "proof_receipts",
        "source_path": AUTOTUNE_SOURCE,
        "schema_versions": schemas,
        "status": "red" if issues else "enumerated",
    }, issues


def autotune_corpus_input(corpus_path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    if not corpus_path.exists():
        return {
            "input_id": "atp-autotune-replay-corpus",
            "source_bead": "asupersync-l9uzgt",
            "family": "proof_receipts",
            "source_path": str(corpus_path),
            "status": "red",
        }, [issue("ATP-NR13", "missing_autotune_replay_corpus", f"missing {corpus_path}")]

    corpus = load_json(corpus_path)
    fixtures = [fixture for fixture in corpus.get("fixtures", []) if isinstance(fixture, dict)]
    decision_receipts = [
        fixture.get("expected_receipt")
        for fixture in fixtures
        if isinstance(fixture.get("expected_receipt"), dict)
    ]
    statuses = sorted(
        {
            str(receipt.get("consumer_status"))
            for receipt in decision_receipts
            if receipt.get("consumer_status")
        }
    )
    pointer_mismatches = []
    for fixture in fixtures:
        receipt = fixture.get("expected_receipt")
        if not isinstance(receipt, dict):
            continue
        pointer = receipt.get("proof_pointer")
        if not isinstance(pointer, dict):
            pointer_mismatches.append(str(fixture.get("fixture_id", "<unknown>")))
            continue
        for field in ["trace_id", "workload_id", "sample_count"]:
            if pointer.get(field) != receipt.get(field):
                pointer_mismatches.append(str(fixture.get("fixture_id", "<unknown>")))
                break
        if pointer.get("receipt_schema_version") != receipt.get("schema_version"):
            pointer_mismatches.append(str(fixture.get("fixture_id", "<unknown>")))

    if corpus.get("schema_version") != "atp-autotune-noisy-pressure-replay-corpus-v1":
        issues.append(issue("ATP-NR13", "unsupported_autotune_corpus_schema", "l9uzgt corpus schema changed"))
    if not decision_receipts:
        issues.append(issue("ATP-NR13", "missing_autotune_decision_receipts", "l9uzgt corpus has no expected decision receipts"))
    if pointer_mismatches:
        issues.append(issue("ATP-NR13", "autotune_receipt_pointer_mismatch", f"proof pointer mismatch in {pointer_mismatches[0]}"))

    return {
        "input_id": "atp-autotune-replay-corpus",
        "source_bead": "asupersync-l9uzgt",
        "family": "proof_receipts",
        "source_path": str(corpus_path),
        "schema_version": corpus.get("schema_version"),
        "update_command": corpus.get("update_command", ""),
        "fixture_count": len(fixtures),
        "decision_receipt_count": len(decision_receipts),
        "consumer_statuses": statuses,
        "status": "red" if issues else "enumerated",
    }, issues


def legacy_inputs(repo_root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows = []
    issues = []
    for row in LEGACY_RELEASE_INPUTS:
        exists = path_exists(repo_root, row["source_path"])
        output = {**row, "status": "enumerated" if exists else "red"}
        rows.append(output)
        if not exists:
            issues.append(issue("ATP-NR13", "missing_legacy_release_input", f"missing {row['source_path']}"))
    return rows, issues


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    repo_root = args.repo_root.resolve()
    dashboard_contract = load_json(args.dashboard_contract)
    proof_manifest = load_json(args.proof_lane_manifest)
    issues_by_id = load_issues(args.issues)
    generated_at = args.generated_at or utc_now()

    gates = []
    issues = []
    for gate in dashboard_contract.get("required_release_gates", []):
        if not isinstance(gate, dict):
            continue
        row, gate_issues = enumerate_gate(gate, repo_root, issues_by_id)
        gates.append(row)
        issues.extend(gate_issues)

    receipt_inputs = []
    schema_row, schema_issues = autotune_schema_input(repo_root)
    receipt_inputs.append(schema_row)
    issues.extend(schema_issues)
    corpus_row, corpus_issues = autotune_corpus_input(args.autotune_corpus)
    receipt_inputs.append(corpus_row)
    issues.extend(corpus_issues)
    legacy_rows, legacy_issues = legacy_inputs(repo_root)
    receipt_inputs.extend(legacy_rows)
    issues.extend(legacy_issues)

    release_blocking_count = sum(1 for row in issues if row["release_blocking"])
    coverage_families = sorted(
        {
            str(row.get("family"))
            for row in [*gates, *receipt_inputs]
            if row.get("family")
        }
    )
    first_blocker = next((row["message"] for row in issues if row["release_blocking"]), "")

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "source_of_truth": {
            "dashboard_contract": str(args.dashboard_contract),
            "proof_lane_manifest": str(args.proof_lane_manifest),
            "autotune_corpus": str(args.autotune_corpus),
            "issues": str(args.issues),
        },
        "release_decision": {
            "ready": release_blocking_count == 0,
            "verdict": "green" if release_blocking_count == 0 else "red",
            "first_blocker": first_blocker,
        },
        "summary": {
            "gate_count": len(gates),
            "receipt_input_count": len(receipt_inputs),
            "release_blocking_count": release_blocking_count,
            "coverage_families": coverage_families,
        },
        "proof_lane_manifest": proof_lane_summary(proof_manifest),
        "gates": gates,
        "receipt_inputs": receipt_inputs,
        "issues": issues,
        "safety": {
            "non_mutating": True,
            "cargo_executed": False,
            "git_mutated": False,
            "files_deleted": False,
            "reads_contracts_only": True,
        },
    }


def render_summary(report: dict[str, Any]) -> str:
    summary = report["summary"]
    decision = report["release_decision"]
    return (
        f"ATP release proof aggregator: {decision['verdict']}\n"
        f"release_blocking_count={summary['release_blocking_count']}\n"
        f"gate_count={summary['gate_count']}\n"
        f"receipt_input_count={summary['receipt_input_count']}\n"
        f"first_blocker={decision['first_blocker']}\n"
    )


def main() -> int:
    args = parse_args()
    report = build_report(args)
    if args.output == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        sys.stdout.write(render_summary(report))

    if report["summary"]["release_blocking_count"] and not args.allow_red:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
