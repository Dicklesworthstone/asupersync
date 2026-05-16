#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SIGNOFF_PATH="${REPO_ROOT}/artifacts/reality_check_gap_closure_signoff_v1.json"
REPORT_PATH="${REALITY_CHECK_SIGNOFF_REPORT_PATH:-${REPO_ROOT}/target/reality-check-signoff/asupersync-rcksgn/signoff-report.json}"

mkdir -p "$(dirname "${REPORT_PATH}")"

python3 - "$REPO_ROOT" "$SIGNOFF_PATH" "$REPORT_PATH" <<'PY'
import json
import os
import subprocess
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
signoff_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
signoff = json.loads(signoff_path.read_text())
drifts = []
events = []


def repo_path(relative):
    return repo_root / relative


def record(scenario_id, **fields):
    row = {"bead_id": "asupersync-rcksgn", "scenario_id": scenario_id, **fields}
    events.append(row)
    parts = [f"bead_id={row['bead_id']}", f"scenario_id={scenario_id}"]
    for key in sorted(k for k in row if k not in {"bead_id", "scenario_id"}):
        value = row[key]
        if isinstance(value, (list, dict)):
            value = json.dumps(value, sort_keys=True, separators=(",", ":"))
        parts.append(f"{key}={value}")
    print(" ".join(parts))


def require(condition, failure):
    if not condition:
        drifts.append(failure)


def commit_exists(commit):
    if not (repo_root / ".git").exists():
        return True
    result = subprocess.run(
        ["git", "-C", str(repo_root), "cat-file", "-e", f"{commit}^{{commit}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.returncode == 0


def cargo_command_has_target_dir(command):
    return "cargo " not in command or (
        "rch exec -- env " in command and "CARGO_TARGET_DIR=" in command
    )


required_gap_ids = set(signoff.get("required_gap_ids", []))
gap_rows = signoff.get("gap_rows", [])
actual_gap_ids = {row.get("gap_id") for row in gap_rows}
missing_gap_ids = sorted(required_gap_ids - actual_gap_ids)
extra_gap_ids = sorted(actual_gap_ids - required_gap_ids)
for gap_id in missing_gap_ids:
    drifts.append(f"missing_gap_row:{gap_id}")
for gap_id in extra_gap_ids:
    drifts.append(f"unexpected_gap_row:{gap_id}")
record(
    "gap-row-inventory",
    required_gap_count=len(required_gap_ids),
    actual_gap_count=len(actual_gap_ids),
    missing_gap_count=len(missing_gap_ids),
    extra_gap_count=len(extra_gap_ids),
    verdict="pass" if not missing_gap_ids and not extra_gap_ids else "fail",
    first_failure=(missing_gap_ids + extra_gap_ids + [""])[0],
)

dependency_status = signoff.get("dependency_status", {})
jsonl_state = dependency_status.get("jsonl_reality_check_state", {})
open_items = jsonl_state.get("open_items", [])
open_ids = {item.get("bead_id") for item in open_items}
expected_open = set()
require(
    dependency_status.get("dependencies_closed_before_signoff") is True,
    "dependency_status:not_all_dependencies_closed",
)
require(open_ids == expected_open, f"unexpected_open_reality_check_items:{sorted(open_ids)}")
require(jsonl_state.get("closed_count") == 16, "final_reality_check_closed_count_mismatch")
record(
    "dependency-status",
    dependency_status="passed"
    if dependency_status.get("dependencies_closed_before_signoff") is True
    else "failed",
    open_reality_check_items=sorted(open_ids),
    closed_count=jsonl_state.get("closed_count", 0),
    verdict="pass" if open_ids == expected_open else "fail",
    first_failure="" if open_ids == expected_open else ",".join(sorted(open_ids)),
)

diagnostics = signoff.get("control_plane_diagnostics", {})
br_cycles = diagnostics.get("br_dep_cycles_json", {})
br_list = diagnostics.get("br_list_json", {})
final_bv = diagnostics.get("bv_robot_plan_reality_check_after_close", {})
require(br_cycles.get("status") == "timed_out", "br_dep_cycles_degradation_not_recorded")
require(br_cycles.get("exit_code") == 124, "br_dep_cycles_exit_code_not_recorded")
require(br_list.get("status") == "failed_external_lock", "br_list_degradation_not_recorded")
require(".beads/.write.lock" in br_list.get("error", ""), "br_list_lock_error_not_recorded")
require(final_bv.get("open_count") == 0, "final_bv_open_count_not_zero")
require(final_bv.get("closed_count") == 16, "final_bv_closed_count_mismatch")
require(final_bv.get("total_actionable") == 0, "final_bv_actionable_not_zero")
record(
    "graph-status",
    graph_status="fallback_passed",
    br_dep_cycles_status=br_cycles.get("status", ""),
    br_list_status=br_list.get("status", ""),
    bv_single_actionable=diagnostics.get("bv_robot_plan_reality_check", {}).get(
        "single_actionable", ""
    ),
    final_open_count=final_bv.get("open_count", ""),
    final_actionable=final_bv.get("total_actionable", ""),
    verdict="pass",
    first_failure="",
)

proof_command_count = 0
failed_or_blocked_commands = []
stale_closed_bead_count = 0
for row in gap_rows:
    gap_id = row.get("gap_id", "")
    commit = row.get("commit", "")
    require(len(commit) == 40 and all(c in "0123456789abcdefABCDEF" for c in commit), f"bad_commit:{gap_id}")
    require(commit_exists(commit), f"missing_commit:{gap_id}:{commit}")
    tracker_commit = row.get("tracker_commit")
    if tracker_commit:
        require(commit_exists(tracker_commit), f"missing_tracker_commit:{gap_id}:{tracker_commit}")

    artifacts = row.get("artifact_paths", [])
    missing_artifacts = [path for path in artifacts if not repo_path(path).exists()]
    for path in missing_artifacts:
        drifts.append(f"missing_artifact:{gap_id}:{path}")

    commands = row.get("proof_commands", [])
    proof_command_count += len(commands)
    passing_commands = [cmd for cmd in commands if cmd.get("status") == "passed"]
    for cmd in commands:
        command_text = cmd.get("command", "")
        require(
            cargo_command_has_target_dir(command_text),
            f"bare_cargo_proof_command:{gap_id}:{command_text}",
        )
    non_passing = [
        f"{gap_id}:{cmd.get('command', '')}"
        for cmd in commands
        if cmd.get("status") != "passed"
    ]
    failed_or_blocked_commands.extend(non_passing)
    require(passing_commands, f"no_passing_proof_command:{gap_id}")
    require(artifacts, f"no_durable_artifact:{gap_id}")
    require(row.get("closure_status") == "fully_closed", f"row_not_fully_closed:{gap_id}")
    require(row.get("residual_risks"), f"missing_residual_risk:{gap_id}")
    if row.get("stale_closed_tracker_repair") is True:
        stale_closed_bead_count += 1
    record(
        "gap-row",
        gap_id=gap_id,
        closing_bead=row.get("closing_bead", ""),
        support_class=row.get("support_class_after", ""),
        proof_commands=len(commands),
        missing_artifacts=len(missing_artifacts),
        non_passing_commands=len(non_passing),
        stale_closed_tracker_repair=row.get("stale_closed_tracker_repair", False),
        verdict="pass" if not missing_artifacts and not non_passing and passing_commands else "fail",
        first_failure=(missing_artifacts + non_passing + [""])[0],
    )

fresh = signoff.get("fresh_signoff_commands", [])
for cmd in fresh:
    command_text = cmd.get("command", "")
    command_id = cmd.get("command_id", "")
    require(
        cargo_command_has_target_dir(command_text),
        f"bare_cargo_fresh_signoff_command:{command_id}:{command_text}",
    )
no_tokio = next(
    (cmd for cmd in fresh if cmd.get("command_id") == "no-tokio-default-normal-graph-rerun"),
    {},
)
require(no_tokio.get("status") == "passed", "no_tokio_rerun_not_passed")
require(
    no_tokio.get("observed_signal") == "warning: nothing to print.",
    "no_tokio_rerun_signal_mismatch",
)

invariants = signoff.get("signoff_invariants", {})
require(
    invariants.get("stale_closed_bead_count") == stale_closed_bead_count,
    "stale_closed_count_mismatch",
)
require(
    invariants.get("failed_or_blocked_required_proof_commands") == [],
    "required_proof_commands_failed_or_blocked",
)

verdict = "passed" if not drifts and not failed_or_blocked_commands else "failed"
first_failure = (drifts + failed_or_blocked_commands + [""])[0]
report = {
    "bead_id": "asupersync-rcksgn",
    "graph_status": "fallback_passed",
    "dependency_status": "passed"
    if dependency_status.get("dependencies_closed_before_signoff") is True
    else "failed",
    "proof_command_count": proof_command_count,
    "failed_or_blocked_commands": failed_or_blocked_commands,
    "stale_closed_bead_count": stale_closed_bead_count,
    "artifact_path": os.path.relpath(report_path, repo_root),
    "verdict": verdict,
    "first_failure": first_failure,
    "events": events,
    "drifts": drifts,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
record(
    "summary",
    graph_status=report["graph_status"],
    dependency_status=report["dependency_status"],
    proof_command_count=proof_command_count,
    failed_or_blocked_commands=json.dumps(failed_or_blocked_commands, sort_keys=True),
    stale_closed_bead_count=stale_closed_bead_count,
    artifact_path=report["artifact_path"],
    verdict=verdict,
    first_failure=first_failure,
)

if verdict != "passed":
    sys.exit(1)
PY
