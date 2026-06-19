#!/usr/bin/env bash
# Validate the SLO policy bundle contract fixtures.
#
# Default mode is a deterministic catalog smoke that writes accepted/rejected
# fixture rows without invoking cargo. Use --input-jsonl for fail-closed JSONL
# validation, --check-rch-log for local-fallback rejection, and --execute-rch
# to run the Rust contract tests through rch.

set -euo pipefail

ARTIFACT="artifacts/slo_policy_bundle_contract_v1.json"
OUTPUT_ROOT="target/slo-policy-bundle"
RUN_ID="manual"
INPUT_JSONL=""
EXECUTE_RCH=0
CHECK_RCH_LOG=""
RCH_BIN="${RCH_BIN:-rch}"
CARGO_BIN="${CARGO_BIN:-cargo}"
RCH_LOCAL_FALLBACK_PATTERN='^\[RCH\] local \(|local fallback|fallback to local|falling back to local|executing locally'

usage() {
  cat <<'USAGE'
Usage:
  bash scripts/validate_slo_policy_bundle.sh [--artifact PATH] [--output-root DIR] [--run-id ID] [--check-rch-log PATH] [--execute-rch]
  bash scripts/validate_slo_policy_bundle.sh --input-jsonl PATH
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact)
      ARTIFACT="$2"
      shift 2
      ;;
    --output-root)
      OUTPUT_ROOT="$2"
      shift 2
      ;;
    --run-id)
      RUN_ID="$2"
      shift 2
      ;;
    --input-jsonl)
      INPUT_JSONL="$2"
      shift 2
      ;;
    --execute-rch)
      EXECUTE_RCH=1
      shift
      ;;
    --check-rch-log)
      CHECK_RCH_LOG="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

OUTDIR="${OUTPUT_ROOT}/${RUN_ID}"
REPORT="${OUTDIR}/slo-policy-bundle-run.json"
MARKDOWN="${OUTDIR}/slo-policy-bundle-run.md"
LOG="${OUTDIR}/slo-policy-bundle-events.ndjson"
DETAIL_LOG="${OUTDIR}/slo-brownout-e2e-detail.log"
RCH_LOG="${OUTDIR}/slo-policy-bundle-rch.log"
mkdir -p "$OUTDIR"

if [[ -n "$INPUT_JSONL" ]]; then
  python3 - "$ARTIFACT" "$INPUT_JSONL" <<'PY'
import json
import sys
from pathlib import Path

artifact_path = Path(sys.argv[1])
input_path = Path(sys.argv[2])

required_fields = {"scenario_id", "bead_id", "accepted", "issue_kinds", "policy_id", "artifact_path"}
try:
    artifact = json.loads(artifact_path.read_text())
    required_fields = set(artifact.get("required_log_fields") or required_fields)
except Exception:
    pass

rows = 0
for line_no, line in enumerate(input_path.read_text().splitlines(), start=1):
    if not line.strip():
        continue
    try:
        event = json.loads(line)
    except Exception as error:
        print(json.dumps({
            "accepted": False,
            "issue_kinds": ["malformed_json"],
            "line": line_no,
            "message": str(error),
            "path": str(input_path),
        }, sort_keys=True))
        raise SystemExit(1)
    missing = sorted(field for field in required_fields if field not in event)
    if missing:
        print(json.dumps({
            "accepted": False,
            "issue_kinds": ["missing_required_field"],
            "line": line_no,
            "missing_fields": missing,
            "path": str(input_path),
        }, sort_keys=True))
        raise SystemExit(1)
    rows += 1

print(json.dumps({"accepted": True, "path": str(input_path), "rows": rows}, sort_keys=True))
PY
  exit $?
fi

python3 - "$ARTIFACT" "$REPORT" "$MARKDOWN" "$LOG" "$DETAIL_LOG" <<'PY'
import json
import sys
from pathlib import Path

artifact_path = Path(sys.argv[1])
report_path = Path(sys.argv[2])
markdown_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
detail_log_path = Path(sys.argv[5])

try:
    artifact = json.loads(artifact_path.read_text())
except Exception as error:
    print(json.dumps({
        "accepted": False,
        "issue_kinds": ["malformed_json"],
        "message": str(error),
        "path": str(artifact_path),
    }, sort_keys=True))
    raise SystemExit(1)

required = {
    "schema_version",
    "bead_id",
    "module",
    "policy_bundle_schema_version",
    "workload_classes",
    "latency_units",
    "validation_issue_kinds",
    "compiler_schema_version",
    "compiler_statuses",
    "compiler_blocker_kinds",
    "lab_replay_contract_version",
    "lab_replay_statuses",
    "proof_report_bead_id",
    "proof_report_schema_version",
    "proof_report_statuses",
    "proof_report_issue_kinds",
    "proof_report_gate",
    "runtime_enforcement_bead_id",
    "runtime_enforcement_report_schema_version",
    "runtime_enforcement_statuses",
    "runtime_enforcement_issue_kinds",
    "runtime_enforcement_contract",
    "lab_brownout_e2e_bead_id",
    "lab_brownout_e2e_contract_version",
    "lab_brownout_e2e_contract",
    "lab_brownout_e2e_scenarios",
    "lab_brownout_e2e_failure_receipts",
    "required_bundle_fields",
    "gate_contract",
    "scenarios",
    "compiler_scenarios",
    "lab_replay_scenarios",
    "proof_report_scenarios",
    "runtime_enforcement_scenarios",
    "e2e_script",
    "required_log_fields",
    "proof_commands",
}
expected_workload_classes = {"control_plane", "data_plane", "background", "agent_swarm"}
expected_latency_units = {"milliseconds", "microseconds"}
expected_issue_kinds = {
    "malformed_json",
    "unsupported_schema_version",
    "missing_required_field",
    "non_monotonic_percentile",
    "invalid_unit",
    "missing_no_win_fallback",
    "secret_like_material",
    "external_path",
    "stale_profile_hash",
    "unsupported_workload_class",
    "duplicate_objective",
    "impossible_deadline",
    "oversized_field",
    "redaction_failure",
}
expected_compiler_statuses = {"compiled", "no_win", "blocked"}
expected_compiler_blocker_kinds = {
    "invalid_bundle",
    "impossible_objective",
    "missing_capacity_evidence",
    "unsupported_workload_class",
    "conflicting_fallback_declaration",
}
expected_lab_replay_statuses = {
    "passed",
    "brownout",
    "rejected",
    "no_win",
    "stale_evidence",
    "cancelled",
    "blocked",
}
expected_proof_report_statuses = {
    "pass",
    "fail",
    "blocked",
    "degraded",
    "no_win",
    "unsupported",
    "stale_evidence",
}
expected_proof_report_issue_kinds = {
    "malformed_report",
    "unsupported_schema_version",
    "missing_required_field",
    "missing_rch_command",
    "stale_profile_hash",
    "missing_no_win_receipt",
    "redaction_failure",
    "secret_like_material",
    "non_passing_status",
    "oversized_field",
}
expected_runtime_enforcement_statuses = {
    "pass",
    "degraded",
    "no_win",
    "blocked",
    "stale_evidence",
    "unsupported",
    "malformed",
}
expected_runtime_enforcement_issue_kinds = {
    "application_invalid",
    "policy_rejected",
    "cancelled",
    "queue_wait_exceeded",
    "memory_pressure_exceeded",
    "fd_pressure_exceeded",
    "timer_queue_exceeded",
    "unsupported_optional_work_class",
    "optional_work_brownout",
    "no_win_fallback",
    "stale_profile_hash",
    "missing_rch_command",
    "missing_no_win_receipt",
    "redaction_failure",
    "secret_like_material",
    "malformed_report",
    "local_rch_fallback",
}
expected_brownout_e2e_issue_kinds = {
    "unsupported_schema_version",
    "missing_required_field",
    "missing_region_evidence",
    "missing_task_completion_evidence",
    "missing_obligation_resolution_evidence",
    "missing_drain_evidence",
    "missing_finalizer_evidence",
    "missing_quiescence_evidence",
    "runtime_invariant_violation",
    "oracle_violation",
    "missing_operator_interpretation",
    "unsupported_claim",
}
expected_brownout_non_claims = {
    "not a throughput benchmark",
    "not a broad production enforcement claim",
    "not proof of RCH fleet availability",
}


def cargo_command_has_target_dir(command):
    return "cargo " not in command or (
        "rch exec -- env " in command and "CARGO_TARGET_DIR=" in command
    )

def bool_token(value):
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "null"


required_bundle_fields = {
    "schema_version",
    "policy_id",
    "workload_class",
    "latency_objectives",
    "cleanup_deadline_ms",
    "max_queue_wait_ms",
    "resource_pressure",
    "no_win_fallback",
    "provenance",
    "redaction",
}

validation_errors = []
missing = sorted(required - artifact.keys())
if missing:
    validation_errors.append({"kind": "missing_required_field", "field": "artifact", "missing": missing})
if artifact.get("schema_version") != "slo-policy-bundle-contract-v1":
    validation_errors.append({"kind": "unsupported_schema_version", "field": "schema_version"})
if artifact.get("policy_bundle_schema_version") != 1:
    validation_errors.append({"kind": "unsupported_schema_version", "field": "policy_bundle_schema_version"})
if set(artifact.get("workload_classes") or []) != expected_workload_classes:
    validation_errors.append({"kind": "invalid_unit", "field": "workload_classes"})
if set(artifact.get("latency_units") or []) != expected_latency_units:
    validation_errors.append({"kind": "invalid_unit", "field": "latency_units"})
if set(artifact.get("validation_issue_kinds") or []) != expected_issue_kinds:
    validation_errors.append({"kind": "missing_required_field", "field": "validation_issue_kinds"})
if artifact.get("compiler_schema_version") != "slo-budget-admission-compiler-v1":
    validation_errors.append({"kind": "unsupported_schema_version", "field": "compiler_schema_version"})
if set(artifact.get("compiler_statuses") or []) != expected_compiler_statuses:
    validation_errors.append({"kind": "missing_required_field", "field": "compiler_statuses"})
if set(artifact.get("compiler_blocker_kinds") or []) != expected_compiler_blocker_kinds:
    validation_errors.append({"kind": "missing_required_field", "field": "compiler_blocker_kinds"})
if artifact.get("lab_replay_contract_version") != "slo-lab-replay-contract-v1":
    validation_errors.append({"kind": "unsupported_schema_version", "field": "lab_replay_contract_version"})
if set(artifact.get("lab_replay_statuses") or []) != expected_lab_replay_statuses:
    validation_errors.append({"kind": "missing_required_field", "field": "lab_replay_statuses"})
if artifact.get("proof_report_schema_version") != "slo-proof-report-v1":
    validation_errors.append({"kind": "unsupported_schema_version", "field": "proof_report_schema_version"})
if set(artifact.get("proof_report_statuses") or []) != expected_proof_report_statuses:
    validation_errors.append({"kind": "missing_required_field", "field": "proof_report_statuses"})
if set(artifact.get("proof_report_issue_kinds") or []) != expected_proof_report_issue_kinds:
    validation_errors.append({"kind": "missing_required_field", "field": "proof_report_issue_kinds"})
if artifact.get("runtime_enforcement_report_schema_version") != "slo-runtime-enforcement-proof-report-v1":
    validation_errors.append({"kind": "unsupported_schema_version", "field": "runtime_enforcement_report_schema_version"})
if set(artifact.get("runtime_enforcement_statuses") or []) != expected_runtime_enforcement_statuses:
    validation_errors.append({"kind": "missing_required_field", "field": "runtime_enforcement_statuses"})
if set(artifact.get("runtime_enforcement_issue_kinds") or []) != expected_runtime_enforcement_issue_kinds:
    validation_errors.append({"kind": "missing_required_field", "field": "runtime_enforcement_issue_kinds"})
if artifact.get("lab_brownout_e2e_contract_version") != "slo-lab-brownout-e2e-receipt-v1":
    validation_errors.append({"kind": "unsupported_schema_version", "field": "lab_brownout_e2e_contract_version"})
e2e_contract = artifact.get("lab_brownout_e2e_contract") or {}
if set(e2e_contract.get("fail_closed_for") or []) != expected_brownout_e2e_issue_kinds:
    validation_errors.append({"kind": "missing_required_field", "field": "lab_brownout_e2e_contract.fail_closed_for"})
if set(e2e_contract.get("non_claims") or []) != expected_brownout_non_claims:
    validation_errors.append({"kind": "missing_required_field", "field": "lab_brownout_e2e_contract.non_claims"})
proof_report_gate = artifact.get("proof_report_gate") or {}
if set(proof_report_gate.get("accepted_statuses") or []) != {"pass", "degraded", "no_win"}:
    validation_errors.append({"kind": "missing_required_field", "field": "proof_report_gate.accepted_statuses"})
if "rch exec" not in str(proof_report_gate.get("command_rendering") or ""):
    validation_errors.append({"kind": "missing_required_field", "field": "proof_report_gate.command_rendering"})
if not required_bundle_fields.issubset(set(artifact.get("required_bundle_fields") or [])):
    validation_errors.append({"kind": "missing_required_field", "field": "required_bundle_fields"})

events = []
accepted_count = 0
rejected_count = 0
malformed_count = 0
scenario_ids = set()
required_log_fields = set(artifact.get("required_log_fields") or [])

for scenario in artifact.get("scenarios") or []:
    scenario_id = scenario.get("scenario_id")
    if not scenario_id:
        validation_errors.append({"kind": "missing_required_field", "field": "scenario_id"})
        continue
    if scenario_id in scenario_ids:
        validation_errors.append({"kind": "duplicate_objective", "field": scenario_id})
    scenario_ids.add(scenario_id)

    expected = scenario.get("expected") or {}
    issue_kinds = list(expected.get("issue_kinds") or [])
    accepted = bool(expected.get("accepted", False))
    policy_id = (scenario.get("bundle") or {}).get("policy_id", "")
    if accepted:
        accepted_count += 1
        if issue_kinds:
            validation_errors.append({"kind": "invalid_unit", "field": scenario_id})
    else:
        rejected_count += 1
        if not issue_kinds:
            validation_errors.append({"kind": "missing_required_field", "field": scenario_id})
    if "malformed_json" in issue_kinds:
        malformed_count += 1
        if "fixture_document" not in scenario:
            validation_errors.append({"kind": "missing_required_field", "field": f"{scenario_id}.fixture_document"})
    elif "bundle" not in scenario:
        validation_errors.append({"kind": "missing_required_field", "field": f"{scenario_id}.bundle"})

    unknown_issues = sorted(set(issue_kinds) - expected_issue_kinds)
    if unknown_issues:
        validation_errors.append({"kind": "unsupported_schema_version", "field": scenario_id, "unknown_issues": unknown_issues})

    event = {
        "scenario_id": scenario_id,
        "bead_id": artifact.get("bead_id", ""),
        "accepted": accepted,
        "issue_kinds": issue_kinds,
        "policy_id": policy_id,
        "artifact_path": str(artifact_path),
    }
    event_missing = sorted(field for field in required_log_fields if field not in event)
    if event_missing:
        validation_errors.append({"kind": "missing_required_field", "field": scenario_id, "missing": event_missing})
    events.append(event)

if accepted_count == 0:
    validation_errors.append({"kind": "missing_required_field", "field": "accepted_scenarios"})
if rejected_count == 0:
    validation_errors.append({"kind": "missing_required_field", "field": "rejected_scenarios"})
if malformed_count == 0:
    validation_errors.append({"kind": "malformed_json", "field": "malformed_scenarios"})

compiled_count = 0
no_win_or_blocked_count = 0
for compiler_scenario in artifact.get("compiler_scenarios") or []:
    scenario_id = compiler_scenario.get("scenario_id")
    if not scenario_id:
        validation_errors.append({"kind": "missing_required_field", "field": "compiler_scenario_id"})
        continue
    expected = compiler_scenario.get("expected") or {}
    status = expected.get("status")
    blocker_kinds = list(expected.get("blocker_kinds") or [])
    if status not in expected_compiler_statuses:
        validation_errors.append({"kind": "unsupported_schema_version", "field": scenario_id})
    unknown_blockers = sorted(set(blocker_kinds) - expected_compiler_blocker_kinds)
    if unknown_blockers:
        validation_errors.append({"kind": "unsupported_schema_version", "field": scenario_id, "unknown_blockers": unknown_blockers})
    if status == "compiled":
        compiled_count += 1
        if blocker_kinds:
            validation_errors.append({"kind": "invalid_unit", "field": scenario_id})
    elif status in {"no_win", "blocked"}:
        no_win_or_blocked_count += 1
        if status == "blocked" and not blocker_kinds:
            validation_errors.append({"kind": "missing_required_field", "field": scenario_id})

    event = {
        "scenario_id": scenario_id,
        "bead_id": artifact.get("compiler_bead_id", artifact.get("bead_id", "")),
        "accepted": status == "compiled",
        "issue_kinds": blocker_kinds,
        "policy_id": compiler_scenario.get("policy_id", ""),
        "artifact_path": str(artifact_path),
        "compiler_status": status,
        "blocker_kinds": blocker_kinds,
        "no_win_fallback": bool(expected.get("no_win_fallback", False)),
    }
    event_missing = sorted(field for field in required_log_fields if field not in event)
    if event_missing:
        validation_errors.append({"kind": "missing_required_field", "field": scenario_id, "missing": event_missing})
    events.append(event)

if compiled_count == 0:
    validation_errors.append({"kind": "missing_required_field", "field": "compiled_compiler_scenarios"})
if no_win_or_blocked_count == 0:
    validation_errors.append({"kind": "missing_required_field", "field": "no_win_or_blocked_compiler_scenarios"})

replay_statuses_seen = set()
for replay_scenario in artifact.get("lab_replay_scenarios") or []:
    scenario_id = replay_scenario.get("scenario_id")
    if not scenario_id:
        validation_errors.append({"kind": "missing_required_field", "field": "lab_replay_scenario_id"})
        continue
    expected = replay_scenario.get("expected") or {}
    replay_status = expected.get("replay_status")
    issue_kinds = list(expected.get("issue_kinds") or [])
    if replay_status not in expected_lab_replay_statuses:
        validation_errors.append({"kind": "unsupported_schema_version", "field": scenario_id})
    replay_statuses_seen.add(replay_status)
    runtime_application_issues = set(artifact.get("runtime_application_issue_kinds") or [])
    runtime_admission_issues = set(artifact.get("runtime_admission_issue_kinds") or [])
    unknown_issues = sorted(
        set(issue_kinds)
        - expected_issue_kinds
        - expected_compiler_blocker_kinds
        - runtime_application_issues
        - runtime_admission_issues
    )
    if unknown_issues:
        validation_errors.append({"kind": "unsupported_schema_version", "field": scenario_id, "unknown_issues": unknown_issues})
    proof_command = replay_scenario.get("proof_command") or ""
    if "rch exec" not in proof_command or not cargo_command_has_target_dir(proof_command):
        validation_errors.append({"kind": "missing_required_field", "field": f"{scenario_id}.proof_command"})

    event = {
        "scenario_id": scenario_id,
        "bead_id": artifact.get("lab_replay_bead_id", artifact.get("bead_id", "")),
        "accepted": replay_status in {"passed", "brownout"},
        "issue_kinds": issue_kinds,
        "policy_id": replay_scenario.get("policy_id", ""),
        "artifact_path": str(artifact_path),
        "lab_replay_status": replay_status,
        "admitted_work_units": expected.get("admitted_work_units", 0),
        "rejected_work_units": expected.get("rejected_work_units", 0),
        "optional_work_units_browned_out": expected.get("optional_work_units_browned_out", 0),
        "cleanup_deadline_misses": expected.get("cleanup_deadline_misses", 0),
        "fallback_reason": expected.get("fallback_reason"),
        "proof_command": proof_command,
    }
    event_missing = sorted(field for field in required_log_fields if field not in event)
    if event_missing:
        validation_errors.append({"kind": "missing_required_field", "field": scenario_id, "missing": event_missing})
    events.append(event)

required_replay_statuses = {"passed", "brownout", "no_win", "blocked"}
missing_replay_statuses = sorted(required_replay_statuses - replay_statuses_seen)
if missing_replay_statuses:
    validation_errors.append({"kind": "missing_required_field", "field": "lab_replay_scenarios", "missing": missing_replay_statuses})

proof_report_statuses_seen = set()
proof_report_count = 0
for proof_scenario in artifact.get("proof_report_scenarios") or []:
    scenario_id = proof_scenario.get("scenario_id")
    if not scenario_id:
        validation_errors.append({"kind": "missing_required_field", "field": "proof_report_scenario_id"})
        continue
    expected = proof_scenario.get("expected") or {}
    status = expected.get("status")
    accepted = bool(expected.get("accepted", False))
    success = bool(expected.get("success", False))
    issue_kinds = list(expected.get("issue_kinds") or [])
    if status not in expected_proof_report_statuses:
        validation_errors.append({"kind": "unsupported_schema_version", "field": scenario_id})
    proof_report_statuses_seen.add(status)
    proof_report_count += 1
    unknown_issues = sorted(set(issue_kinds) - expected_proof_report_issue_kinds)
    if unknown_issues:
        validation_errors.append({"kind": "unsupported_schema_version", "field": scenario_id, "unknown_issues": unknown_issues})
    if "fixture_document" in proof_scenario:
        if issue_kinds != ["malformed_report"]:
            validation_errors.append({"kind": "malformed_json", "field": scenario_id})
        report = {}
    else:
        report = proof_scenario.get("report") or {}
        if not report:
            validation_errors.append({"kind": "missing_required_field", "field": f"{scenario_id}.report"})
        if report.get("schema_version") != "slo-proof-report-v1":
            validation_errors.append({"kind": "unsupported_schema_version", "field": f"{scenario_id}.report.schema_version"})
        if report.get("status") != status:
            validation_errors.append({"kind": "missing_required_field", "field": f"{scenario_id}.report.status"})
        if not report.get("report_id") or not report.get("policy_id") or not report.get("human_summary"):
            validation_errors.append({"kind": "missing_required_field", "field": scenario_id})
        proof_commands = list(report.get("proof_commands") or [])
        if not proof_commands:
            validation_errors.append({"kind": "missing_required_field", "field": f"{scenario_id}.proof_commands"})
        for index, command in enumerate(proof_commands):
            rendered = command.get("command") or ""
            if "rch exec" not in rendered or not cargo_command_has_target_dir(rendered):
                validation_errors.append({"kind": "missing_rch_command", "field": f"{scenario_id}.proof_commands[{index}]"})
        if status == "no_win":
            receipt = report.get("no_win_receipt")
            if not receipt:
                validation_errors.append({"kind": "missing_no_win_receipt", "field": scenario_id})
            else:
                receipt_command = str(receipt.get("proof_command") or "")
                if "rch exec" not in receipt_command or not cargo_command_has_target_dir(receipt_command):
                    validation_errors.append({"kind": "missing_rch_command", "field": f"{scenario_id}.no_win_receipt.proof_command"})
        if status == "degraded" and "degraded" not in str(report.get("human_summary") or "").lower():
            validation_errors.append({"kind": "missing_required_field", "field": f"{scenario_id}.human_summary"})
        if status == "no_win":
            summary = str(report.get("human_summary") or "").lower()
            if "no-win" not in summary and "no win" not in summary:
                validation_errors.append({"kind": "missing_required_field", "field": f"{scenario_id}.human_summary"})
        provenance = report.get("provenance") or {}
        if status == "stale_evidence" and provenance.get("observed_profile_hash") == provenance.get("profile_hash"):
            validation_errors.append({"kind": "stale_profile_hash", "field": f"{scenario_id}.provenance"})
        if not (report.get("redaction") or {}).get("passed", False):
            validation_errors.append({"kind": "redaction_failure", "field": f"{scenario_id}.redaction"})
        if not list(report.get("rows") or []):
            validation_errors.append({"kind": "missing_required_field", "field": f"{scenario_id}.rows"})
    if success and status != "pass":
        validation_errors.append({"kind": "missing_required_field", "field": f"{scenario_id}.success"})
    if accepted and status not in {"pass", "degraded", "no_win"}:
        validation_errors.append({"kind": "missing_required_field", "field": f"{scenario_id}.accepted"})

    event = {
        "scenario_id": scenario_id,
        "bead_id": artifact.get("proof_report_bead_id", artifact.get("bead_id", "")),
        "accepted": accepted,
        "issue_kinds": issue_kinds,
        "policy_id": report.get("policy_id", ""),
        "artifact_path": str(artifact_path),
        "proof_report_status": status,
        "proof_report_success": success,
        "gate_accepted": accepted,
        "proof_report_issue_kinds": issue_kinds,
        "proof_commands_count": len(report.get("proof_commands") or []),
        "no_win_receipt": bool(report.get("no_win_receipt")),
    }
    event_missing = sorted(field for field in required_log_fields if field not in event)
    if event_missing:
        validation_errors.append({"kind": "missing_required_field", "field": scenario_id, "missing": event_missing})
    events.append(event)

runtime_enforcement_statuses_seen = set()
runtime_enforcement_count = 0
for runtime_scenario in artifact.get("runtime_enforcement_scenarios") or []:
    scenario_id = runtime_scenario.get("scenario_id")
    if not scenario_id:
        validation_errors.append({"kind": "missing_required_field", "field": "runtime_enforcement_scenario_id"})
        continue
    expected = runtime_scenario.get("expected") or {}
    status = expected.get("status")
    accepted = bool(expected.get("accepted", False))
    success = bool(expected.get("success", False))
    issue_kinds = list(expected.get("issue_kinds") or [])
    proof_command = runtime_scenario.get("proof_command") or ""
    redaction = runtime_scenario.get("redaction") or {}
    runtime_enforcement_statuses_seen.add(status)
    runtime_enforcement_count += 1
    if status not in expected_runtime_enforcement_statuses:
        validation_errors.append({"kind": "unsupported_schema_version", "field": scenario_id})
    unknown_issues = sorted(set(issue_kinds) - expected_runtime_enforcement_issue_kinds)
    if unknown_issues:
        validation_errors.append({"kind": "unsupported_schema_version", "field": scenario_id, "unknown_issues": unknown_issues})
    if "rch exec" not in proof_command or not cargo_command_has_target_dir(proof_command):
        validation_errors.append({"kind": "missing_rch_command", "field": f"{scenario_id}.proof_command"})
    if not redaction.get("passed", False):
        validation_errors.append({"kind": "redaction_failure", "field": f"{scenario_id}.redaction"})
    if "secret" in proof_command.lower() or "token" in proof_command.lower():
        validation_errors.append({"kind": "secret_like_material", "field": f"{scenario_id}.proof_command"})
    if success and status != "pass":
        validation_errors.append({"kind": "missing_required_field", "field": f"{scenario_id}.success"})
    if accepted and status not in {"pass", "degraded", "no_win"}:
        validation_errors.append({"kind": "missing_required_field", "field": f"{scenario_id}.accepted"})
    if status == "no_win" and not expected.get("fallback_reason"):
        validation_errors.append({"kind": "missing_no_win_receipt", "field": scenario_id})
    if status == "stale_evidence" and "stale_profile_hash" not in issue_kinds:
        validation_errors.append({"kind": "stale_profile_hash", "field": scenario_id})
    if status == "malformed" and "malformed_report" not in issue_kinds:
        validation_errors.append({"kind": "malformed_report", "field": scenario_id})

    event = {
        "scenario_id": scenario_id,
        "bead_id": artifact.get("runtime_enforcement_bead_id", artifact.get("bead_id", "")),
        "accepted": accepted,
        "issue_kinds": issue_kinds,
        "policy_id": runtime_scenario.get("policy_id", ""),
        "artifact_path": str(artifact_path),
        "runtime_enforcement_status": status,
        "runtime_admission_status": expected.get("runtime_admission_status"),
        "lab_replay_status": expected.get("lab_replay_status"),
        "admitted_work_units": expected.get("admitted_work_units", 0),
        "rejected_work_units": expected.get("rejected_work_units", 0),
        "optional_work_units_browned_out": expected.get("optional_work_units_browned_out", 0),
        "cleanup_deadline_misses": expected.get("cleanup_deadline_misses", 0),
        "fallback_reason": expected.get("fallback_reason"),
        "proof_command": proof_command,
        "proof_command_source": runtime_scenario.get("proof_command_source", ""),
        "redaction_policy_id": redaction.get("policy_id", ""),
    }
    event_missing = sorted(field for field in required_log_fields if field not in event)
    if event_missing:
        validation_errors.append({"kind": "missing_required_field", "field": scenario_id, "missing": event_missing})
    events.append(event)

missing_proof_statuses = sorted(expected_proof_report_statuses - proof_report_statuses_seen)
if missing_proof_statuses:
    validation_errors.append({"kind": "missing_required_field", "field": "proof_report_scenarios", "missing": missing_proof_statuses})
missing_runtime_enforcement_statuses = sorted(
    expected_runtime_enforcement_statuses - runtime_enforcement_statuses_seen
)
if missing_runtime_enforcement_statuses:
    validation_errors.append({
        "kind": "missing_required_field",
        "field": "runtime_enforcement_scenarios",
        "missing": missing_runtime_enforcement_statuses,
    })

lab_brownout_e2e_count = 0
for e2e_scenario in artifact.get("lab_brownout_e2e_scenarios") or []:
    scenario_id = e2e_scenario.get("scenario_id")
    if not scenario_id:
        validation_errors.append({"kind": "missing_required_field", "field": "lab_brownout_e2e_scenario_id"})
        continue
    expected = e2e_scenario.get("expected") or {}
    proof_command = e2e_scenario.get("proof_command") or ""
    issue_kinds = list(expected.get("issue_kinds") or [])
    lab_brownout_e2e_count += 1
    if expected.get("receipt_status") != "green":
        validation_errors.append({"kind": "missing_required_field", "field": f"{scenario_id}.receipt_status"})
    if "rch exec" not in proof_command or not cargo_command_has_target_dir(proof_command):
        validation_errors.append({"kind": "missing_rch_command", "field": f"{scenario_id}.proof_command"})
    if set(expected.get("non_claims") or []) != expected_brownout_non_claims:
        validation_errors.append({"kind": "missing_required_field", "field": f"{scenario_id}.non_claims"})
    if expected.get("final_quiescent") is not True:
        validation_errors.append({"kind": "missing_quiescence_evidence", "field": scenario_id})
    if expected.get("obligation_state") != "resolved":
        validation_errors.append({"kind": "missing_obligation_resolution_evidence", "field": scenario_id})
    if (expected.get("drain_completed_count") or 0) < (expected.get("drain_requested_count") or 0):
        validation_errors.append({"kind": "missing_drain_evidence", "field": scenario_id})
    if (expected.get("finalizer_completed_count") or 0) < (expected.get("finalizer_expected_count") or 0):
        validation_errors.append({"kind": "missing_finalizer_evidence", "field": scenario_id})
    if not expected.get("operator_interpretation"):
        validation_errors.append({"kind": "missing_operator_interpretation", "field": scenario_id})
    unknown_issues = sorted(set(issue_kinds) - expected_brownout_e2e_issue_kinds)
    if unknown_issues:
        validation_errors.append({"kind": "unsupported_schema_version", "field": scenario_id, "unknown_issues": unknown_issues})
    event = {
        "scenario_id": scenario_id,
        "bead_id": artifact.get("lab_brownout_e2e_bead_id", artifact.get("bead_id", "")),
        "accepted": True,
        "issue_kinds": issue_kinds,
        "policy_id": e2e_scenario.get("policy_id", ""),
        "artifact_path": str(artifact_path),
        "schema_version": artifact.get("lab_brownout_e2e_contract_version"),
        "receipt_status": expected.get("receipt_status"),
        "pressure_transition": expected.get("pressure_transition"),
        "region_ids": expected.get("region_ids", []),
        "task_counts": expected.get("task_counts", {}),
        "obligation_state": expected.get("obligation_state"),
        "cancellation_requested_count": expected.get("cancellation_requested_count", 0),
        "cancellation_observed_count": expected.get("cancellation_observed_count", 0),
        "drain_requested_count": expected.get("drain_requested_count", 0),
        "drain_completed_count": expected.get("drain_completed_count", 0),
        "finalizer_expected_count": expected.get("finalizer_expected_count", 0),
        "finalizer_completed_count": expected.get("finalizer_completed_count", 0),
        "final_quiescent": expected.get("final_quiescent"),
        "runtime_invariant_violations": expected.get("runtime_invariant_violations", []),
        "oracle_violations": expected.get("oracle_violations", []),
        "operator_interpretation": expected.get("operator_interpretation"),
        "non_claims": expected.get("non_claims", []),
        "proof_command": proof_command,
    }
    event_missing = sorted(field for field in e2e_contract.get("required_event_fields", []) if field not in event)
    if event_missing:
        validation_errors.append({"kind": "missing_required_field", "field": scenario_id, "missing": event_missing})
    events.append(event)

red_receipt_count = 0
for fixture in artifact.get("lab_brownout_e2e_failure_receipts") or []:
    scenario_id = fixture.get("scenario_id")
    expected = fixture.get("expected") or {}
    issue_kinds = list(expected.get("issue_kinds") or [])
    red_receipt_count += 1
    unknown_issues = sorted(set(issue_kinds) - expected_brownout_e2e_issue_kinds)
    if unknown_issues:
        validation_errors.append({"kind": "unsupported_schema_version", "field": scenario_id, "unknown_issues": unknown_issues})
    if expected.get("receipt_status") != "red":
        validation_errors.append({"kind": "missing_required_field", "field": f"{scenario_id}.receipt_status"})
    if "missing_drain_evidence" not in issue_kinds and "missing_finalizer_evidence" not in issue_kinds:
        validation_errors.append({"kind": "missing_required_field", "field": f"{scenario_id}.red_issue"})
    receipt = fixture.get("receipt") or {}
    event = {
        "scenario_id": scenario_id,
        "bead_id": artifact.get("lab_brownout_e2e_bead_id", artifact.get("bead_id", "")),
        "accepted": False,
        "issue_kinds": issue_kinds,
        "policy_id": fixture.get("policy_id", ""),
        "artifact_path": str(artifact_path),
        "schema_version": receipt.get("schema_version"),
        "receipt_status": expected.get("receipt_status"),
        "pressure_transition": receipt.get("pressure_transition"),
        "region_ids": receipt.get("region_ids", []),
        "task_counts": receipt.get("task_counts", {}),
        "obligation_state": receipt.get("obligation_state"),
        "cancellation_requested_count": receipt.get("cancellation_requested_count", 0),
        "cancellation_observed_count": receipt.get("cancellation_observed_count", 0),
        "drain_requested_count": receipt.get("drain_requested_count", 0),
        "drain_completed_count": receipt.get("drain_completed_count", 0),
        "finalizer_expected_count": receipt.get("finalizer_expected_count", 0),
        "finalizer_completed_count": receipt.get("finalizer_completed_count", 0),
        "final_quiescent": receipt.get("final_quiescent"),
        "runtime_invariant_violations": receipt.get("runtime_invariant_violations", []),
        "oracle_violations": receipt.get("oracle_violations", []),
        "operator_interpretation": receipt.get("operator_interpretation"),
        "non_claims": receipt.get("non_claims", []),
        "proof_command": fixture.get("proof_command", ""),
    }
    events.append(event)

log_path.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events))
markdown_lines = [
    "# SLO Policy Bundle Run",
    "",
    f"- artifact: {artifact_path}",
    f"- schema: {artifact.get('schema_version')}",
    f"- brownout_e2e_schema: {artifact.get('lab_brownout_e2e_contract_version')}",
    f"- validation_errors: {len(validation_errors)}",
    "",
    "| scenario | receipt_status | transition | quiescent | drain | finalizer |",
    "|---|---:|---|---:|---:|---:|",
]
for event in events:
    if "receipt_status" not in event:
        continue
    markdown_lines.append(
        "| {scenario_id} | {receipt_status} | {pressure_transition} | {final_quiescent} | {drain_completed_count}/{drain_requested_count} | {finalizer_completed_count}/{finalizer_expected_count} |".format(**event)
    )
markdown_path.write_text("\n".join(markdown_lines) + "\n")
detail_lines = []
for event in events:
    if "receipt_status" not in event:
        continue
    detail_event = dict(event)
    detail_event["final_quiescent"] = bool_token(event.get("final_quiescent"))
    detail_lines.append(
        "scenario={scenario_id} receipt_status={receipt_status} pressure_transition={pressure_transition} final_quiescent={final_quiescent} drain={drain_completed_count}/{drain_requested_count} finalizer={finalizer_completed_count}/{finalizer_expected_count}".format(**detail_event)
    )
detail_log_path.write_text("\n".join(detail_lines) + "\n")

report = {
    "accepted": not validation_errors,
    "artifact": str(artifact_path),
    "bead_id": artifact.get("bead_id", ""),
    "schema_version": artifact.get("schema_version"),
    "scenario_count": len(events),
    "accepted_count": accepted_count,
    "rejected_count": rejected_count,
    "malformed_count": malformed_count,
    "proof_report_count": proof_report_count,
    "runtime_enforcement_count": runtime_enforcement_count,
    "lab_brownout_e2e_count": lab_brownout_e2e_count,
    "lab_brownout_e2e_red_receipt_count": red_receipt_count,
    "events_log": str(log_path),
    "markdown_report": str(markdown_path),
    "detail_log": str(detail_log_path),
    "validation_errors": validation_errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps(report, sort_keys=True))
raise SystemExit(0 if not validation_errors else 1)
PY

if [[ -n "$CHECK_RCH_LOG" ]]; then
  if grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN" "$CHECK_RCH_LOG"; then
    printf '{"accepted":false,"issue_kinds":["local_rch_fallback"],"path":%s}\n' \
      "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$CHECK_RCH_LOG")" >&2
    exit 86
  fi
fi

if [[ "$EXECUTE_RCH" -eq 1 ]]; then
  if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
    echo "rch binary not found: $RCH_BIN" >&2
    exit 127
  fi
  RCH_CMD=(
    "$RCH_BIN" exec --
    env
    "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_slo_policy_compiler_script"
    CARGO_INCREMENTAL=0
    CARGO_PROFILE_TEST_DEBUG=0
    "RUSTFLAGS=-C debuginfo=0"
    "$CARGO_BIN" test -p asupersync --test slo_policy_bundle_contract --features test-internals -- --nocapture
  )
  printf '%q ' "${RCH_CMD[@]}" > "$RCH_LOG"
  printf '\n' >> "$RCH_LOG"
  set +e
  "${RCH_CMD[@]}" 2>&1 | tee -a "$RCH_LOG"
  rch_status=${PIPESTATUS[0]}
  set -e
  if grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN" "$RCH_LOG"; then
    exit 86
  fi
  exit "$rch_status"
fi
