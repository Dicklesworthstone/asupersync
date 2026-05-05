#!/usr/bin/env python3
"""Aggregate mock-code-finder child evidence into one proof report."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from typing import Any


SCHEMA_VERSION = "mock-code-finder-evidence-jsonl-schema-v1"
BEAD_ID = "asupersync-oelvq2"
CONTRACT = pathlib.Path("artifacts/mock_code_finder_verification_contract_v1.json")
AGGREGATE_CONTRACT = pathlib.Path("artifacts/mock_code_finder_aggregate_contract_v1.json")
VALIDATOR = pathlib.Path("scripts/validate_mock_code_finder_evidence.py")


class RunnerError(Exception):
    """Raised for invalid child evidence or runner configuration."""


@dataclass(frozen=True)
class ChildSpec:
    child_bead_id: str
    subsystem: str
    script: str
    env_artifact_root: str = "ARTIFACT_ROOT"
    supports_child_args: bool = True
    command: tuple[str, ...] = ()


DEFAULT_CHILDREN = [
    ChildSpec("asupersync-uw9zg9", "observability-otel-w3c", "scripts/run_observability_evidence.sh"),
    ChildSpec("asupersync-hxi1ga", "http2-conformance", "scripts/run_h2_conformance_evidence.sh"),
    ChildSpec("asupersync-kokw3m", "raptorq-rfc6330", "scripts/run_rfc6330_conformance_evidence.sh"),
    ChildSpec("asupersync-zftrj9", "database-postgres-copy-from", "scripts/run_postgres_copy_from_evidence.sh"),
    ChildSpec("asupersync-a5d34a", "runtime-sync", "scripts/run_runtime_sync_invariant_evidence.sh"),
    ChildSpec(
        "asupersync-a45",
        "mock-code-finder-policy",
        "scripts/run_no_mock_policy_evidence.sh",
        env_artifact_root="STUB_SCAN_ARTIFACT_ROOT",
        supports_child_args=False,
    ),
]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def git_state() -> str:
    sha_proc = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        text=True,
        capture_output=True,
        check=False,
    )
    sha = sha_proc.stdout.strip() if sha_proc.returncode == 0 else "unknown"
    dirty_proc = subprocess.run(
        ["git", "status", "--porcelain"],
        text=True,
        capture_output=True,
        check=False,
    )
    if dirty_proc.returncode != 0:
        return f"main@{sha}-tree-state-unavailable"
    dirty = dirty_proc.stdout.strip()
    return f"main@{sha}-dirty" if dirty else f"main@{sha}"


def load_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RunnerError(f"{path}: file does not exist") from exc
    except json.JSONDecodeError as exc:
        raise RunnerError(f"{path}: invalid JSON: {exc}") from exc


def default_child_specs() -> list[ChildSpec]:
    return list(DEFAULT_CHILDREN)


def child_specs_from_config(path: pathlib.Path) -> list[ChildSpec]:
    data = load_json(path)
    children = data.get("children")
    if not isinstance(children, list) or not children:
        raise RunnerError("config children must be a nonempty list")
    specs = []
    for index, child in enumerate(children, 1):
        if not isinstance(child, dict):
            raise RunnerError(f"config children[{index}] must be an object")
        command = child.get("command", [])
        if command and (
            not isinstance(command, list) or not all(isinstance(part, str) for part in command)
        ):
            raise RunnerError(f"config children[{index}].command must be a string list")
        for field in ("child_bead_id", "subsystem"):
            if not isinstance(child.get(field), str) or not child[field]:
                raise RunnerError(f"config children[{index}] must include {field}")
        script = child.get("script", "")
        if command:
            script = command[0]
        if not isinstance(script, str) or not script:
            raise RunnerError(f"config children[{index}] must include script or command")
        specs.append(
            ChildSpec(
                child_bead_id=child["child_bead_id"],
                subsystem=child["subsystem"],
                script=script,
                env_artifact_root=str(child.get("env_artifact_root", "ARTIFACT_ROOT")),
                supports_child_args=bool(child.get("supports_child_args", False if command else True)),
                command=tuple(command),
            )
        )
    return specs


def command_for_child(child: ChildSpec, child_root: pathlib.Path, run_id: str, mode: str) -> list[str]:
    if child.command:
        return list(child.command)
    command = ["bash", child.script]
    if child.supports_child_args:
        command.extend(["--execute", "--artifact-root", str(child_root), "--run-id", run_id])
        if mode in {"local", "ci"}:
            command.append("--local")
    return command


def env_for_child(child: ChildSpec, child_root: pathlib.Path, run_id: str, mode: str) -> dict[str, str]:
    env = dict(os.environ)
    env[child.env_artifact_root] = str(child_root)
    if child.env_artifact_root == "STUB_SCAN_ARTIFACT_ROOT":
        env["STUB_SCAN_ARTIFACT_PATH_ROOT"] = str(child_root)
    else:
        env["ARTIFACT_ROOT"] = str(child_root)
    env["RUN_ID"] = run_id
    if mode == "ci":
        env["CI"] = "true"
    return env


def parse_jsonl(path: pathlib.Path) -> list[dict[str, Any]]:
    records = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise RunnerError(f"{path}: JSONL file does not exist") from exc
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RunnerError(f"{path}:{line_number}: malformed JSONL: {exc}") from exc
        if not isinstance(row, dict):
            raise RunnerError(f"{path}:{line_number}: record must be an object")
        records.append(row)
    if not records:
        raise RunnerError(f"{path}: zero scenario records")
    return records


def validate_record_context(record: dict[str, Any], source: pathlib.Path, index: int) -> None:
    if record.get("schema_version") != SCHEMA_VERSION:
        raise RunnerError(f"{source}:{index}: schema_version must be {SCHEMA_VERSION}")
    if "evidence_quality" not in record:
        raise RunnerError(f"{source}:{index}: missing evidence_quality")
    verdict = record.get("verdict")
    if verdict in {"blocked", "unsupported"}:
        context = [
            str(record.get("blocker_bead_id", "")),
            str(record.get("first_failure_line", "")),
            str(record.get("actual_behavior", "")),
        ]
        if not any(item.strip() for item in context):
            raise RunnerError(f"{source}:{index}: {verdict} record lacks blocker/context details")


def run_validator(jsonl: pathlib.Path, summary_output: pathlib.Path) -> None:
    proc = subprocess.run(
        [
            "python3",
            str(VALIDATOR),
            "--contract",
            str(CONTRACT),
            "--jsonl",
            str(jsonl),
            "--summary-output",
            str(summary_output),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RunnerError(
            f"{jsonl}: shared validator failed with exit {proc.returncode}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )


def summarize_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    verdicts: Counter[str] = Counter()
    qualities: Counter[str] = Counter()
    support: Counter[str] = Counter()
    first_failure = ""
    policy_scan_counts: dict[str, Any] = {}
    artifacts = []
    for record in records:
        verdict = str(record.get("verdict", ""))
        verdicts[verdict] += 1
        qualities[str(record.get("evidence_quality", ""))] += 1
        support[str(record.get("support_class", ""))] += 1
        output_artifact = str(record.get("output_artifact", ""))
        if output_artifact:
            artifacts.append(output_artifact)
        if not first_failure and verdict in {"fail", "blocked"}:
            first_failure = str(record.get("first_failure_line", "")) or str(
                record.get("actual_behavior", "")
            )
        if record.get("subsystem") == "mock-code-finder" and "matching_paths=" in str(
            record.get("actual_behavior", "")
        ):
            policy_scan_counts["actual_behavior"] = record["actual_behavior"]
    return {
        "scenario_count": len(records),
        "verdict_counts": dict(sorted(verdicts.items())),
        "evidence_quality_counts": dict(sorted(qualities.items())),
        "support_class_counts": dict(sorted(support.items())),
        "first_failure_line": first_failure,
        "artifact_paths": sorted(set(artifacts)),
        "policy_scan_counts": policy_scan_counts,
    }


def execute_child(
    child: ChildSpec,
    root: pathlib.Path,
    run_id: str,
    mode: str,
) -> dict[str, Any]:
    child_root = root / child.child_bead_id
    child_root.mkdir(parents=True, exist_ok=True)
    stdout_path = child_root / "child.stdout.log"
    stderr_path = child_root / "child.stderr.log"
    command = command_for_child(child, child_root, run_id, mode)
    proc = subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
        env=env_for_child(child, child_root, run_id, mode),
    )
    stdout_path.write_text(proc.stdout, encoding="utf-8")
    stderr_path.write_text(proc.stderr, encoding="utf-8")

    jsonl_paths = sorted(child_root.rglob("*.jsonl"))
    records: list[dict[str, Any]] = []
    validation_errors: list[str] = []
    for jsonl in jsonl_paths:
        try:
            child_records = parse_jsonl(jsonl)
            for index, record in enumerate(child_records, 1):
                validate_record_context(record, jsonl, index)
            run_validator(jsonl, jsonl.with_suffix(jsonl.suffix + ".validation.json"))
            records.extend(child_records)
        except RunnerError as exc:
            validation_errors.append(str(exc))

    if not jsonl_paths:
        validation_errors.append("child emitted zero JSONL artifact files")
    if not records and not validation_errors:
        validation_errors.append("child emitted zero scenario records")
    if proc.returncode != 0:
        validation_errors.append(f"child command exited {proc.returncode}")

    summary = summarize_records(records) if records else {
        "scenario_count": 0,
        "verdict_counts": {},
        "evidence_quality_counts": {},
        "support_class_counts": {},
        "first_failure_line": "",
        "artifact_paths": [],
        "policy_scan_counts": {},
    }
    return {
        "child_bead_id": child.child_bead_id,
        "subsystem": child.subsystem,
        "command": " ".join(command),
        "exit_code": proc.returncode,
        "artifact_root": str(child_root),
        "stdout_log": str(stdout_path),
        "stderr_log": str(stderr_path),
        "jsonl_artifacts": [str(path) for path in jsonl_paths],
        "validation_errors": validation_errors,
        "status": "fail" if validation_errors else "pass",
        **summary,
    }


def aggregate_children(
    children: list[ChildSpec],
    artifact_root: pathlib.Path,
    run_id: str,
    mode: str,
) -> tuple[dict[str, Any], str]:
    started_at = utc_now()
    root = artifact_root / run_id
    root.mkdir(parents=True, exist_ok=True)
    child_rows = [execute_child(child, root, run_id, mode) for child in children]
    finished_at = utc_now()

    verdict_totals: Counter[str] = Counter()
    quality_totals: Counter[str] = Counter()
    support_totals: Counter[str] = Counter()
    first_failure = ""
    for child in child_rows:
        verdict_totals.update(child["verdict_counts"])
        quality_totals.update(child["evidence_quality_counts"])
        support_totals.update(child["support_class_counts"])
        if not first_failure:
            if child["validation_errors"]:
                first_failure = child["validation_errors"][0]
            elif child["first_failure_line"]:
                first_failure = child["first_failure_line"]

    final_verdict = "fail" if any(child["status"] == "fail" for child in child_rows) else "pass"
    aggregate = {
        "schema_version": "mock-code-finder-aggregate-report-v1",
        "bead_id": BEAD_ID,
        "run_id": run_id,
        "mode": mode,
        "git_sha_or_tree_state": git_state(),
        "started_at": started_at,
        "finished_at": finished_at,
        "invoked_by_bead": BEAD_ID,
        "child_count": len(child_rows),
        "scenario_count": sum(child["scenario_count"] for child in child_rows),
        "verdict_counts": dict(sorted(verdict_totals.items())),
        "evidence_quality_counts": dict(sorted(quality_totals.items())),
        "support_class_counts": dict(sorted(support_totals.items())),
        "first_failure_line": first_failure,
        "children": child_rows,
        "final_verdict": final_verdict,
    }
    human = human_summary(aggregate)
    (root / "mock-code-finder-aggregate.summary.md").write_text(human, encoding="utf-8")
    (root / "mock-code-finder-aggregate.json").write_text(
        json.dumps(aggregate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return aggregate, human


def human_summary(aggregate: dict[str, Any]) -> str:
    lines = [
        f"mock-code-finder aggregate run: {aggregate['final_verdict']}",
        f"run_id: {aggregate['run_id']}",
        f"git: {aggregate['git_sha_or_tree_state']}",
        f"scenarios: {aggregate['scenario_count']}",
        f"verdict_counts: {aggregate['verdict_counts']}",
        f"evidence_quality_counts: {aggregate['evidence_quality_counts']}",
    ]
    if aggregate["first_failure_line"]:
        lines.append(f"first_failure: {aggregate['first_failure_line']}")
    lines.append("")
    for child in aggregate["children"]:
        lines.append(
            f"- {child['child_bead_id']} {child['subsystem']}: "
            f"{child['status']} scenarios={child['scenario_count']} "
            f"verdicts={child['verdict_counts']} artifacts={child['jsonl_artifacts']}"
        )
        if child["validation_errors"]:
            lines.append(f"  first_error: {child['validation_errors'][0]}")
    return "\n".join(lines) + "\n"


def list_payload(children: list[ChildSpec], artifact_root: pathlib.Path, run_id: str, mode: str) -> dict[str, Any]:
    root = artifact_root / run_id
    rows = []
    for child in children:
        child_root = root / child.child_bead_id
        rows.append(
            {
                "child_bead_id": child.child_bead_id,
                "subsystem": child.subsystem,
                "artifact_root": str(child_root),
                "command": command_for_child(child, child_root, run_id, mode),
                "env_artifact_root": child.env_artifact_root,
            }
        )
    return {
        "schema_version": "mock-code-finder-aggregate-plan-v1",
        "bead_id": BEAD_ID,
        "run_id": run_id,
        "mode": mode,
        "children": rows,
    }


def write_fixture_script(path: pathlib.Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body, encoding="utf-8")
    path.chmod(0o755)


def fixture_record(verdict: str, evidence_quality: str, support_class: str = "production_live") -> dict[str, Any]:
    blocker = "asupersync-fixture-blocker" if verdict == "blocked" else ""
    return {
        "schema_version": SCHEMA_VERSION,
        "bead_id": "asupersync-fixture",
        "scenario_id": f"fixture-{verdict}",
        "subsystem": "fixture",
        "support_class": support_class,
        "source_files_inspected": ["fixture.sh"],
        "command": "fixture child",
        "rch_command_if_used": "",
        "cargo_features": [],
        "test_filter": f"fixture-{verdict}",
        "env_keys_required": ["ARTIFACT_ROOT"],
        "deterministic_seed_or_fixture_id": "fixture-seed",
        "input_artifact": "fixture.sh",
        "output_artifact": "fixture.log",
        "expected_behavior": f"fixture emits {verdict}",
        "actual_behavior": f"fixture emitted {verdict} with deterministic log context",
        "verdict": verdict,
        "first_failure_line": "fixture:1" if verdict in {"fail", "blocked"} else "",
        "duration_ms": 0,
        "git_sha_or_tree_state": "fixture",
        "blocker_bead_id": blocker,
        "evidence_quality": evidence_quality,
    }


def run_self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="asupersync-oelvq2-self-test-") as tmp_raw:
        tmp = pathlib.Path(tmp_raw)
        scripts_dir = tmp / "children"
        scripts_dir.mkdir()

        specs = []
        for verdict, quality, support in [
            ("pass", "live", "production_live"),
            ("blocked", "blocked", "blocked_external"),
            ("unsupported", "unsupported", "explicitly_unsupported"),
            ("expected_fail", "expected_fail", "production_live"),
            ("fixture_only", "fixture_only", "fixture_reference"),
        ]:
            script = scripts_dir / f"{verdict}.sh"
            record = json.dumps(fixture_record(verdict, quality, support), sort_keys=True)
            write_fixture_script(
                script,
                f'mkdir -p "$ARTIFACT_ROOT"\necho "fixture {verdict}" > "$ARTIFACT_ROOT/{verdict}.log"\n'
                f"printf '%s\\n' '{record}' > \"$ARTIFACT_ROOT/{verdict}.jsonl\"\n",
            )
            specs.append(
                {
                    "child_bead_id": f"asupersync-fixture-{verdict}",
                    "subsystem": f"fixture-{verdict}",
                    "command": ["bash", str(script)],
                }
            )

        config = tmp / "config.json"
        config.write_text(json.dumps({"children": specs}, indent=2), encoding="utf-8")
        aggregate, _ = aggregate_children(
            child_specs_from_config(config),
            tmp / "artifacts",
            "self-test-pass",
            "local",
        )
        if aggregate["final_verdict"] != "pass" or aggregate["scenario_count"] != 5:
            raise RunnerError("self-test pass fixture aggregate did not pass")

        bad_script = scripts_dir / "malformed.sh"
        write_fixture_script(
            bad_script,
            'mkdir -p "$ARTIFACT_ROOT"\nprintf "%s\\n" "{not-json" > "$ARTIFACT_ROOT/bad.jsonl"\n',
        )
        bad_config = tmp / "bad-config.json"
        bad_config.write_text(
            json.dumps(
                {
                    "children": [
                        {
                            "child_bead_id": "asupersync-fixture-malformed",
                            "subsystem": "fixture-malformed",
                            "command": ["bash", str(bad_script)],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        bad_aggregate, _ = aggregate_children(
            child_specs_from_config(bad_config),
            tmp / "bad-artifacts",
            "self-test-fail",
            "local",
        )
        if bad_aggregate["final_verdict"] != "fail":
            raise RunnerError("self-test malformed fixture did not fail")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["local", "rch", "ci"], default="local")
    parser.add_argument("--ci", action="store_true", help="Alias for --mode ci")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--config-json", type=pathlib.Path)
    parser.add_argument("--artifact-root", type=pathlib.Path, default=pathlib.Path("artifacts/mock-code-finder/asupersync-oelvq2"))
    parser.add_argument("--run-id", default="current")
    parser.add_argument("--child", action="append", default=[], help="Limit to child bead id or subsystem")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    mode = "ci" if args.ci else args.mode
    try:
        if args.self_test:
            run_self_test()
            print("mock-code-finder aggregate self-test: pass")
            return 0

        children = child_specs_from_config(args.config_json) if args.config_json else default_child_specs()
        if args.child:
            wanted = set(args.child)
            children = [
                child for child in children if child.child_bead_id in wanted or child.subsystem in wanted
            ]
            if not children:
                raise RunnerError(f"no children matched filter: {sorted(wanted)}")

        plan = list_payload(children, args.artifact_root, args.run_id, mode)
        if args.list or args.dry_run:
            print(json.dumps(plan, indent=2, sort_keys=True))
            return 0

        aggregate, human = aggregate_children(children, args.artifact_root, args.run_id, mode)
        print(human, end="")
        print(
            f"aggregate_json={args.artifact_root / args.run_id / 'mock-code-finder-aggregate.json'}",
            file=sys.stderr,
        )
        print(
            f"aggregate_summary={args.artifact_root / args.run_id / 'mock-code-finder-aggregate.summary.md'}",
            file=sys.stderr,
        )
        return 0 if aggregate["final_verdict"] == "pass" else 1
    except RunnerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
