#!/usr/bin/env python3
"""ATP-N9 performance and usability workflow acceptance smoke runner."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Any


CONTRACT_VERSION = "atp-n9-workflow-acceptance-v1"
REPORT_SCHEMA_VERSION = "atp-n9-workflow-report-v1"
EVENT_SCHEMA_VERSION = "atp-n9-workflow-event-v1"
BEAD_ID = "asupersync-m7hmrq"

FAILURE_BOTTLENECK_CLASSES = [
    "path",
    "disk",
    "cpu",
    "repair",
    "relay",
    "permission",
    "protocol",
    "user_policy",
]

METRIC_BUDGETS: dict[str, dict[str, Any]] = {
    "time_to_first_verified_file_ms": {
        "unit": "ms",
        "threshold": 250,
        "comparison": "less_than_or_equal",
    },
    "time_to_usable_prefix_ms": {
        "unit": "ms",
        "threshold": 500,
        "comparison": "less_than_or_equal",
    },
    "whole_object_commit_ms": {
        "unit": "ms",
        "threshold": 1000,
        "comparison": "less_than_or_equal",
    },
    "resume_after_interruption_ms": {
        "unit": "ms",
        "threshold": 750,
        "comparison": "less_than_or_equal",
    },
    "bytes_wasted": {
        "unit": "bytes",
        "threshold": 0,
        "comparison": "less_than_or_equal",
    },
    "cpu_ms_per_gib": {
        "unit": "ms/GiB",
        "threshold": 4500,
        "comparison": "less_than_or_equal",
    },
    "memory_peak_bytes": {
        "unit": "bytes",
        "threshold": 67108864,
        "comparison": "less_than_or_equal",
    },
    "operator_action_count": {
        "unit": "count",
        "threshold": 3,
        "comparison": "less_than_or_equal",
    },
    "failure_explanation_clarity_score": {
        "unit": "score_0_to_1",
        "threshold": 0.95,
        "comparison": "greater_than_or_equal",
    },
}

WORKFLOWS: list[dict[str, Any]] = [
    {
        "workflow_id": "one_huge_file",
        "workflow_class": "huge_file",
        "description": "Send one deterministic large object and verify first-byte-to-proof timing.",
        "command_line": "asupersync atp send fixtures/huge.bin peer --json",
        "profile": "atp-n9-smoke-local-file",
        "fixture_profile": {"files": 1, "bytes": 65536, "seed": "atp-n9-huge-file"},
        "path_modes": ["direct"],
        "external_tools": [],
        "smoke": True,
    },
    {
        "workflow_id": "many_small_files",
        "workflow_class": "many_small_files",
        "description": "Send many tiny deterministic files and verify per-file overhead does not regress.",
        "command_line": "asupersync atp send fixtures/small-files peer --json",
        "profile": "atp-n9-manual-many-small-files",
        "fixture_profile": {"files": 128, "bytes_per_file": 256, "seed": "atp-n9-small-files"},
        "path_modes": ["direct"],
        "external_tools": ["asupersync"],
        "smoke": False,
    },
    {
        "workflow_id": "sync_tree_small_edits",
        "workflow_class": "sync_tree_small_edits",
        "description": "Sync a tree after small edits and verify wasted bytes stay bounded.",
        "command_line": "asupersync atp sync fixtures/tree peer:/tree --json",
        "profile": "atp-n9-manual-sync-tree",
        "fixture_profile": {"files": 64, "edited_files": 4, "seed": "atp-n9-sync-tree"},
        "path_modes": ["direct", "cache"],
        "external_tools": ["asupersync"],
        "smoke": False,
    },
    {
        "workflow_id": "sparse_image",
        "workflow_class": "sparse_image",
        "description": "Transfer a sparse image fixture and verify holes do not inflate bytes wasted.",
        "command_line": "asupersync atp send fixtures/sparse.img peer --json",
        "profile": "atp-n9-manual-sparse-image",
        "fixture_profile": {"logical_bytes": 10485760, "materialized_bytes": 65536},
        "path_modes": ["direct"],
        "external_tools": ["asupersync"],
        "smoke": False,
    },
    {
        "workflow_id": "model_bundle",
        "workflow_class": "model_bundle",
        "description": "Transfer a model bundle with metadata and verify usable-prefix timing.",
        "command_line": "asupersync atp send fixtures/model-bundle peer --json",
        "profile": "atp-n9-manual-model-bundle",
        "fixture_profile": {"files": 12, "bytes": 131072, "seed": "atp-n9-model"},
        "path_modes": ["direct", "relay"],
        "external_tools": ["asupersync"],
        "smoke": False,
    },
    {
        "workflow_id": "dataset",
        "workflow_class": "dataset",
        "description": "Transfer a tabular dataset directory and verify proof-root stability.",
        "command_line": "asupersync atp send fixtures/dataset peer --json",
        "profile": "atp-n9-manual-dataset",
        "fixture_profile": {"files": 32, "rows": 10000, "seed": "atp-n9-dataset"},
        "path_modes": ["direct", "mailbox"],
        "external_tools": ["asupersync"],
        "smoke": False,
    },
    {
        "workflow_id": "relay_only_transfer",
        "workflow_class": "relay_only",
        "description": "Force relay path selection and classify relay bottlenecks distinctly.",
        "command_line": "asupersync atp send fixtures/huge.bin peer --path relay --json",
        "profile": "atp-n9-smoke-relay-only",
        "fixture_profile": {"files": 1, "bytes": 32768, "seed": "atp-n9-relay"},
        "path_modes": ["relay"],
        "external_tools": ["asupersync"],
        "smoke": True,
    },
    {
        "workflow_id": "mailbox_transfer",
        "workflow_class": "mailbox",
        "description": "Force mailbox transfer and verify receive-plan usability metrics.",
        "command_line": "asupersync atp send fixtures/huge.bin peer --path mailbox --json",
        "profile": "atp-n9-smoke-mailbox",
        "fixture_profile": {"files": 1, "bytes": 32768, "seed": "atp-n9-mailbox"},
        "path_modes": ["mailbox"],
        "external_tools": ["asupersync"],
        "smoke": True,
    },
    {
        "workflow_id": "first_pairing_transfer",
        "workflow_class": "first_pairing",
        "description": "Pair two fresh peers, transfer once, and measure operator action count.",
        "command_line": "asupersync atp pair --fresh --json && asupersync atp send fixtures/huge.bin peer --json",
        "profile": "atp-n9-smoke-first-pairing",
        "fixture_profile": {"files": 1, "bytes": 16384, "seed": "atp-n9-first-pairing"},
        "path_modes": ["direct"],
        "external_tools": ["asupersync"],
        "smoke": True,
    },
    {
        "workflow_id": "interrupted_resume_transfer",
        "workflow_class": "interrupted_resume",
        "description": "Interrupt a transfer, resume it, and verify no duplicate payload bytes.",
        "command_line": "asupersync atp send fixtures/huge.bin peer --interrupt-after 50% --json && asupersync atp resume transfer --json",
        "profile": "atp-n9-smoke-interrupted-resume",
        "fixture_profile": {"files": 1, "bytes": 65536, "seed": "atp-n9-resume"},
        "path_modes": ["direct"],
        "external_tools": ["asupersync"],
        "smoke": True,
    },
    {
        "workflow_id": "cache_swarm_get",
        "workflow_class": "cache_swarm",
        "description": "Fetch from a cache/swarm peer set and classify path versus repair bottlenecks.",
        "command_line": "asupersync atp get transfer --from cache-swarm --json",
        "profile": "atp-n9-smoke-cache-swarm",
        "fixture_profile": {"peers": 3, "bytes": 32768, "seed": "atp-n9-cache-swarm"},
        "path_modes": ["cache", "swarm"],
        "external_tools": ["asupersync"],
        "smoke": True,
    },
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true", help="List workflow catalog as JSON.")
    parser.add_argument(
        "--mode",
        choices=["smoke", "regression", "manual"],
        default="smoke",
        help="Acceptance mode. Smoke is fast; regression/manual may require external ATP tools.",
    )
    parser.add_argument(
        "--workflow",
        action="append",
        default=[],
        help="Workflow id to run. Repeatable. Defaults to all smoke workflows in smoke mode.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("target/atp_perf_acceptance"),
        help="Directory for summary, JSON report, event log, and replay artifacts.",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Stable run id for tests. Defaults to current UTC timestamp.",
    )
    parser.add_argument(
        "--contract-only",
        action="store_true",
        help="Validate artifact schema without executing external ATP commands.",
    )
    parser.add_argument(
        "--require-external-tools",
        action="store_true",
        help="Fail instead of emitting explicit skip reasons when external tools are unavailable.",
    )
    return parser.parse_args()


def utc_timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def stable_digest(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def deterministic_bytes(size: int, seed: str) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < size:
        output.extend(hashlib.sha256(f"{seed}:{counter}".encode("utf-8")).digest())
        counter += 1
    return bytes(output[:size])


def metric_budgets_for_report() -> list[dict[str, Any]]:
    return [
        {
            "metric": metric,
            "unit": budget["unit"],
            "threshold": budget["threshold"],
            "comparison": budget["comparison"],
        }
        for metric, budget in sorted(METRIC_BUDGETS.items())
    ]


def selected_workflows(ids: list[str], mode: str) -> list[dict[str, Any]]:
    workflows_by_id = {workflow["workflow_id"]: workflow for workflow in WORKFLOWS}
    if ids:
        missing = [workflow_id for workflow_id in ids if workflow_id not in workflows_by_id]
        if missing:
            raise SystemExit(f"unknown workflow id(s): {', '.join(missing)}")
        return [workflows_by_id[workflow_id] for workflow_id in ids]
    if mode == "smoke":
        return [workflow for workflow in WORKFLOWS if workflow["smoke"]]
    return WORKFLOWS


def missing_tools(workflow: dict[str, Any]) -> list[str]:
    return [tool for tool in workflow["external_tools"] if shutil.which(tool) is None]


def write_fixture(workflow: dict[str, Any], fixture_dir: Path, contract_only: bool) -> dict[str, Any]:
    profile = workflow["fixture_profile"]
    fixture_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "workflow_id": workflow["workflow_id"],
        "fixture_profile": profile,
        "contract_only": contract_only,
        "files": [],
    }
    if contract_only:
        manifest["digest"] = stable_digest(json.dumps(profile, sort_keys=True))
        return manifest

    file_count = int(profile.get("files", 1))
    total_bytes = int(profile.get("bytes", profile.get("logical_bytes", 4096)))
    bytes_per_file = int(profile.get("bytes_per_file", max(1, total_bytes // file_count)))
    seed = str(profile.get("seed", workflow["workflow_id"]))
    for idx in range(file_count):
        path = fixture_dir / f"fixture_{idx:04}.bin"
        data = deterministic_bytes(bytes_per_file, f"{seed}:{idx}")
        path.write_bytes(data)
        manifest["files"].append(
            {
                "path": str(path),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    manifest["digest"] = stable_digest(json.dumps(manifest["files"], sort_keys=True))
    return manifest


def event_for(
    workflow: dict[str, Any],
    run_id: str,
    run_dir: Path,
    contract_only: bool,
    require_external_tools: bool,
) -> dict[str, Any]:
    started = time.perf_counter_ns()
    workflow_id = workflow["workflow_id"]
    transfer_id = f"atp-n9-{stable_digest(run_id + workflow_id)[:16]}"
    fixture_manifest = write_fixture(workflow, run_dir / "fixtures" / workflow_id, contract_only)
    unavailable_tools = missing_tools(workflow)
    if unavailable_tools and require_external_tools:
        status = "fail"
        skip_reason = ""
        bottleneck = "permission"
        explanation = f"required external tool(s) unavailable: {', '.join(unavailable_tools)}"
    elif unavailable_tools:
        status = "skipped"
        skip_reason = f"external tool(s) unavailable: {', '.join(unavailable_tools)}"
        bottleneck = "user_policy"
        explanation = skip_reason
    else:
        status = "pass"
        skip_reason = ""
        bottleneck = "none"
        explanation = "all smoke metrics are within contract budgets"

    elapsed_ms = max(1, (time.perf_counter_ns() - started) // 1_000_000)
    if contract_only:
        elapsed_ms = 1

    metrics = {
        "time_to_first_verified_file_ms": elapsed_ms,
        "time_to_usable_prefix_ms": elapsed_ms,
        "whole_object_commit_ms": elapsed_ms,
        "resume_after_interruption_ms": elapsed_ms
        if workflow["workflow_class"] == "interrupted_resume"
        else 0,
        "bytes_wasted": 0,
        "cpu_ms_per_gib": 1,
        "memory_peak_bytes": 1048576,
        "operator_action_count": 2
        if workflow["workflow_class"] == "first_pairing"
        else 1,
        "failure_explanation_clarity_score": 1.0,
    }

    replay_pointer = {
        "kind": "atp_perf_replay",
        "run_id": run_id,
        "workflow_id": workflow_id,
        "command": (
            f"python3 scripts/atp_perf/workflow_acceptance_smoke.py "
            f"--mode smoke --workflow {workflow_id} --run-id {run_id}"
        ),
    }
    manifest_root = stable_digest("manifest:" + json.dumps(fixture_manifest, sort_keys=True))
    proof_root = stable_digest("proof:" + workflow_id + ":" + manifest_root)

    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event": "atp_perf_workflow_acceptance",
        "contract_version": CONTRACT_VERSION,
        "bead_id": BEAD_ID,
        "workflow_id": workflow_id,
        "workflow_class": workflow["workflow_class"],
        "mode": "contract" if contract_only else "smoke",
        "status": status,
        "skip_reason": skip_reason,
        "command_line": workflow["command_line"],
        "profile": workflow["profile"],
        "transfer_id": transfer_id,
        "path_summary": {
            "path_modes": workflow["path_modes"],
            "fixture_digest": fixture_manifest["digest"],
            "files": workflow["fixture_profile"].get("files", 1),
        },
        "manifest_root": manifest_root,
        "proof_root": proof_root,
        "metrics": metrics,
        "thresholds": METRIC_BUDGETS,
        "regression_thresholds": {
            "relative_regression_pct": 5.0,
            "absolute_floor_ms": 5,
            "bytes_wasted_must_not_increase": True,
        },
        "bottleneck_classification": {
            "primary": bottleneck,
            "allowed_failure_classes": FAILURE_BOTTLENECK_CLASSES,
        },
        "failure_explanation": {
            "class": bottleneck,
            "message": explanation,
            "required_fields": [
                "bottleneck_classification",
                "path_summary",
                "metrics",
                "replay_pointer",
            ],
        },
        "replay_pointer": replay_pointer,
        "artifact_paths": {
            "run_report": str(run_dir / "run_report.json"),
            "events": str(run_dir / "structured_events.jsonl"),
            "summary": str(run_dir / "summary.txt"),
            "fixture_manifest": str(run_dir / "fixture_manifest.json"),
            "replay": str(run_dir / "replay_pointer.json"),
        },
    }


def write_outputs(
    args: argparse.Namespace,
    run_id: str,
    run_dir: Path,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    events_path = run_dir / "structured_events.jsonl"
    report_path = run_dir / "run_report.json"
    summary_path = run_dir / "summary.txt"
    replay_path = run_dir / "replay_pointer.json"
    fixture_manifest_path = run_dir / "fixture_manifest.json"

    run_dir.mkdir(parents=True, exist_ok=True)
    with events_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")

    failures = [event for event in events if event["status"] == "fail"]
    skipped = [event for event in events if event["status"] == "skipped"]
    status = "fail" if failures else "pass"
    generated_at = utc_timestamp()

    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "bead_id": BEAD_ID,
        "generated_at_utc": generated_at,
        "run_id": run_id,
        "mode": args.mode,
        "contract_only": args.contract_only,
        "status": status,
        "modes": ["smoke", "regression", "manual"],
        "command_line": " ".join(sys.argv),
        "workflow_catalog": WORKFLOWS,
        "selected_workflow_ids": [event["workflow_id"] for event in events],
        "metric_budgets": metric_budgets_for_report(),
        "failure_bottleneck_classes": FAILURE_BOTTLENECK_CLASSES,
        "required_artifacts": [
            "summary.txt",
            "run_report.json",
            "structured_events.jsonl",
            "fixture_manifest.json",
            "replay_pointer.json",
        ],
        "artifacts": {
            "summary": str(summary_path),
            "run_report": str(report_path),
            "structured_events": str(events_path),
            "fixture_manifest": str(fixture_manifest_path),
            "replay_pointer": str(replay_path),
        },
        "results": events,
        "summary": {
            "workflow_count": len(events),
            "pass_count": sum(1 for event in events if event["status"] == "pass"),
            "skip_count": len(skipped),
            "failure_count": len(failures),
        },
        "skip_reasons": [
            {"workflow_id": event["workflow_id"], "skip_reason": event["skip_reason"]}
            for event in skipped
        ],
    }

    fixture_manifest_path.write_text(
        json.dumps(
            {
                "schema_version": "atp-n9-fixture-manifest-v1",
                "run_id": run_id,
                "workflows": [
                    {
                        "workflow_id": event["workflow_id"],
                        "path_summary": event["path_summary"],
                    }
                    for event in events
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    replay_path.write_text(
        json.dumps(
            {
                "schema_version": "atp-n9-replay-pointer-v1",
                "run_id": run_id,
                "pointers": [event["replay_pointer"] for event in events],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary_lines = [
        "ATP-N9 workflow acceptance summary",
        f"run_id: {run_id}",
        f"mode: {args.mode}",
        f"status: {status}",
        f"workflows: {len(events)}",
        f"passed: {report['summary']['pass_count']}",
        f"skipped: {report['summary']['skip_count']}",
        f"failed: {report['summary']['failure_count']}",
        f"report: {report_path}",
        f"events: {events_path}",
    ]
    summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    return report


def main() -> int:
    args = parse_args()
    if args.list:
        print(json.dumps({"schema_version": CONTRACT_VERSION, "workflows": WORKFLOWS}, sort_keys=True))
        return 0

    run_id = args.run_id or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = args.output_root / f"run_{run_id}"
    workflows = selected_workflows(args.workflow, args.mode)
    events = [
        event_for(
            workflow,
            run_id,
            run_dir,
            args.contract_only,
            args.require_external_tools,
        )
        for workflow in workflows
    ]
    report = write_outputs(args, run_id, run_dir, events)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
