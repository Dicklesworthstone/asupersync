#!/usr/bin/env python3
"""CI matrix policy gate for lane coverage, thresholds, and artifacts.

This validator enforces that required CI lanes are represented in the workflow
with explicit job/step/artifact contracts and replay commands.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any


JOB_ID_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$", re.MULTILINE)
STEP_NAME_RE = re.compile(r"^\s*-\s+name:\s*(.+?)\s*$", re.MULTILINE)


class PolicyError(ValueError):
    """Raised when the policy or inputs are malformed."""


@dataclass(frozen=True)
class LanePolicy:
    lane_id: str
    title: str
    owner: str
    required_job_ids: tuple[str, ...]
    required_step_names: tuple[str, ...]
    required_artifact_names: tuple[str, ...]
    replay_command: str
    failure_taxonomy: tuple[str, ...]
    max_failures: int
    required_artifacts_min: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", default=".github/ci_matrix_policy.json", type=Path)
    parser.add_argument("--workflow", type=Path, default=None)
    parser.add_argument("--summary-output", default="", type=Path)
    parser.add_argument("--events-output", default="", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PolicyError(f"missing file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyError(f"invalid JSON at {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise PolicyError(f"policy must be a JSON object: {path}")
    return payload


def require_str(raw: Any, label: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise PolicyError(f"{label} must be a non-empty string")
    return raw


def require_int(raw: Any, label: str, minimum: int = 0) -> int:
    if not isinstance(raw, int) or raw < minimum:
        raise PolicyError(f"{label} must be an integer >= {minimum}")
    return raw


def require_str_list(raw: Any, label: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or not all(isinstance(item, str) and item.strip() for item in raw):
        raise PolicyError(f"{label} must be list[str] with non-empty entries")
    return tuple(raw)


def load_policy(policy_path: Path) -> tuple[dict[str, Any], list[LanePolicy], Path, Path]:
    policy = load_json(policy_path)
    if policy.get("schema_version") != "ci-matrix-policy-v1":
        raise PolicyError("unsupported or missing schema_version")

    output = policy.get("output")
    if not isinstance(output, dict):
        raise PolicyError("output must be an object")
    summary_path = Path(require_str(output.get("summary_path"), "output.summary_path"))
    events_path = Path(require_str(output.get("events_path"), "output.events_path"))

    defaults = policy.get("threshold_defaults", {})
    if not isinstance(defaults, dict):
        raise PolicyError("threshold_defaults must be an object")
    default_max_failures = require_int(defaults.get("max_failures", 0), "threshold_defaults.max_failures")
    default_artifacts_min = require_int(
        defaults.get("required_artifacts_min", 0), "threshold_defaults.required_artifacts_min"
    )

    lanes_raw = policy.get("lanes")
    if not isinstance(lanes_raw, list) or not lanes_raw:
        raise PolicyError("lanes must be a non-empty list")

    lanes: list[LanePolicy] = []
    seen_ids: set[str] = set()
    for idx, lane_raw in enumerate(lanes_raw):
        if not isinstance(lane_raw, dict):
            raise PolicyError(f"lanes[{idx}] must be an object")
        lane_id = require_str(lane_raw.get("lane_id"), f"lanes[{idx}].lane_id")
        if lane_id in seen_ids:
            raise PolicyError(f"duplicate lane_id: {lane_id}")
        seen_ids.add(lane_id)

        thresholds = lane_raw.get("thresholds", {})
        if not isinstance(thresholds, dict):
            raise PolicyError(f"lanes[{idx}].thresholds must be an object")

        lanes.append(
            LanePolicy(
                lane_id=lane_id,
                title=require_str(lane_raw.get("title"), f"lanes[{idx}].title"),
                owner=require_str(lane_raw.get("owner"), f"lanes[{idx}].owner"),
                required_job_ids=require_str_list(
                    lane_raw.get("required_job_ids", []), f"lanes[{idx}].required_job_ids"
                ),
                required_step_names=require_str_list(
                    lane_raw.get("required_step_names", []), f"lanes[{idx}].required_step_names"
                ),
                required_artifact_names=require_str_list(
                    lane_raw.get("required_artifact_names", []), f"lanes[{idx}].required_artifact_names"
                ),
                replay_command=require_str(lane_raw.get("replay_command"), f"lanes[{idx}].replay_command"),
                failure_taxonomy=require_str_list(
                    lane_raw.get("failure_taxonomy", []), f"lanes[{idx}].failure_taxonomy"
                ),
                max_failures=require_int(
                    thresholds.get("max_failures", default_max_failures),
                    f"lanes[{idx}].thresholds.max_failures",
                ),
                required_artifacts_min=require_int(
                    thresholds.get("required_artifacts_min", default_artifacts_min),
                    f"lanes[{idx}].thresholds.required_artifacts_min",
                ),
            )
        )

    return policy, lanes, summary_path, events_path


def collect_workflow_contracts(workflow_text: str) -> tuple[set[str], set[str]]:
    job_ids = {match.group(1).strip() for match in JOB_ID_RE.finditer(workflow_text)}
    step_names = {match.group(1).strip() for match in STEP_NAME_RE.finditer(workflow_text)}
    return job_ids, step_names


def artifact_name_exists(workflow_text: str, artifact_name: str) -> bool:
    return f"name: {artifact_name}" in workflow_text


def evaluate_lane(
    lane: LanePolicy,
    workflow_text: str,
    job_ids: set[str],
    step_names: set[str],
) -> dict[str, Any]:
    missing_job_ids = sorted(job for job in lane.required_job_ids if job not in job_ids)
    missing_steps = sorted(step for step in lane.required_step_names if step not in step_names)
    missing_artifacts = sorted(
        artifact for artifact in lane.required_artifact_names if not artifact_name_exists(workflow_text, artifact)
    )
    missing_contracts = [
        *[f"job:{item}" for item in missing_job_ids],
        *[f"step:{item}" for item in missing_steps],
        *[f"artifact:{item}" for item in missing_artifacts],
    ]
    status = "pass" if not missing_contracts else "fail"
    return {
        "lane_id": lane.lane_id,
        "title": lane.title,
        "owner": lane.owner,
        "status": status,
        "required_job_ids": list(lane.required_job_ids),
        "required_step_names": list(lane.required_step_names),
        "required_artifact_names": list(lane.required_artifact_names),
        "missing_job_ids": missing_job_ids,
        "missing_steps": missing_steps,
        "missing_artifacts": missing_artifacts,
        "missing_contracts": missing_contracts,
        "replay_command": lane.replay_command,
        "failure_taxonomy": list(lane.failure_taxonomy),
        "thresholds": {
            "max_failures": lane.max_failures,
            "required_artifacts_min": lane.required_artifacts_min,
        },
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_ndjson(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True))
            handle.write("\n")


def run_self_tests() -> int:
    sample_policy = {
        "schema_version": "ci-matrix-policy-v1",
        "output": {"summary_path": "artifacts/a.json", "events_path": "artifacts/b.ndjson"},
        "threshold_defaults": {"max_failures": 0, "required_artifacts_min": 0},
        "lanes": [
            {
                "lane_id": "unit",
                "title": "Unit lane",
                "owner": "runtime-core",
                "required_job_ids": ["test"],
                "required_step_names": ["Run unit tests"],
                "required_artifact_names": ["ci-summary-report"],
                "replay_command": "cargo test --lib --all-features",
                "failure_taxonomy": ["unit_assertion_failure"],
                "thresholds": {"max_failures": 0, "required_artifacts_min": 1},
            }
        ],
    }
    policy_path = Path("/tmp/ci_matrix_policy_selftest.json")
    policy_path.write_text(json.dumps(sample_policy), encoding="utf-8")
    _, lanes, _, _ = load_policy(policy_path)

    workflow_pass = """
jobs:
  test:
    steps:
      - name: Run unit tests
  ci-summary-d5:
    steps:
      - name: Upload
        with:
          name: ci-summary-report
"""
    jobs_pass, steps_pass = collect_workflow_contracts(workflow_pass)
    lane_pass = evaluate_lane(lanes[0], workflow_pass, jobs_pass, steps_pass)
    if lane_pass["status"] != "pass":
        raise AssertionError("expected pass lane status")

    workflow_fail = """
jobs:
  docs:
    steps:
      - name: Build documentation
"""
    jobs_fail, steps_fail = collect_workflow_contracts(workflow_fail)
    lane_fail = evaluate_lane(lanes[0], workflow_fail, jobs_fail, steps_fail)
    if lane_fail["status"] != "fail":
        raise AssertionError("expected fail lane status")
    if "job:test" not in lane_fail["missing_contracts"]:
        raise AssertionError("expected missing required job")
    if "step:Run unit tests" not in lane_fail["missing_contracts"]:
        raise AssertionError("expected missing required step")
    if "artifact:ci-summary-report" not in lane_fail["missing_contracts"]:
        raise AssertionError("expected missing artifact contract")

    print("CI matrix policy self-test passed")
    return 0


def main() -> int:
    args = parse_args()
    if args.self_test:
        return run_self_tests()

    policy_path = args.policy
    policy, lanes, default_summary_path, default_events_path = load_policy(policy_path)

    workflow_path = args.workflow or Path(require_str(policy.get("workflow_path"), "workflow_path"))
    workflow_text = workflow_path.read_text(encoding="utf-8")
    workflow_sha256 = sha256_text(workflow_text)
    job_ids, step_names = collect_workflow_contracts(workflow_text)

    lane_reports = [evaluate_lane(lane, workflow_text, job_ids, step_names) for lane in lanes]
    failing_lane_ids = [lane["lane_id"] for lane in lane_reports if lane["status"] != "pass"]
    overall_status = "pass" if not failing_lane_ids else "fail"

    summary_path = args.summary_output if str(args.summary_output) else default_summary_path
    events_path = args.events_output if str(args.events_output) else default_events_path

    summary = {
        "schema_version": "ci-matrix-policy-report-v1",
        "generated_at": utc_now(),
        "policy_id": policy.get("policy_id"),
        "policy_path": str(policy_path),
        "workflow_path": str(workflow_path),
        "workflow_sha256": workflow_sha256,
        "status": overall_status,
        "lane_count": len(lane_reports),
        "failing_lane_count": len(failing_lane_ids),
        "failing_lane_ids": failing_lane_ids,
        "lanes": lane_reports,
    }

    events: list[dict[str, Any]] = []
    for lane in lane_reports:
        events.append(
            {
                "schema_version": "ci-matrix-policy-event-v1",
                "generated_at": summary["generated_at"],
                "lane_id": lane["lane_id"],
                "owner": lane["owner"],
                "status": lane["status"],
                "missing_contracts": lane["missing_contracts"],
                "replay_command": lane["replay_command"],
                "failure_taxonomy": lane["failure_taxonomy"],
            }
        )

    write_json(summary_path, summary)
    write_ndjson(events_path, events)
    print(f"CI matrix summary: {summary_path}")
    print(f"CI matrix events: {events_path}")

    if overall_status != "pass":
        for lane in lane_reports:
            if lane["status"] != "pass":
                missing = ", ".join(lane["missing_contracts"])
                print(f"CI matrix lane failed: {lane['lane_id']} [{missing}]")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
