#!/usr/bin/env bash
# Validate the SLO policy bundle contract fixtures.
#
# Default mode is a deterministic catalog smoke that writes accepted/rejected
# fixture rows without invoking cargo. Use --input-jsonl for fail-closed JSONL
# validation. Pass --execute-rch to run the Rust contract tests through rch.

set -euo pipefail

ARTIFACT="artifacts/slo_policy_bundle_contract_v1.json"
OUTPUT_ROOT="target/slo-policy-bundle"
RUN_ID="manual"
INPUT_JSONL=""
EXECUTE_RCH=0
RCH_BIN="${RCH_BIN:-rch}"

usage() {
  cat <<'USAGE'
Usage:
  bash scripts/validate_slo_policy_bundle.sh [--artifact PATH] [--output-root DIR] [--run-id ID] [--execute-rch]
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
LOG="${OUTDIR}/slo-policy-bundle-events.ndjson"
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

python3 - "$ARTIFACT" "$REPORT" "$LOG" <<'PY'
import json
import sys
from pathlib import Path

artifact_path = Path(sys.argv[1])
report_path = Path(sys.argv[2])
log_path = Path(sys.argv[3])

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
    "required_bundle_fields",
    "gate_contract",
    "scenarios",
    "compiler_scenarios",
    "lab_replay_scenarios",
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
expected_lab_replay_statuses = {"passed", "brownout", "no_win", "blocked"}
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
    unknown_issues = sorted(set(issue_kinds) - expected_issue_kinds - expected_compiler_blocker_kinds)
    if unknown_issues:
        validation_errors.append({"kind": "unsupported_schema_version", "field": scenario_id, "unknown_issues": unknown_issues})
    proof_command = replay_scenario.get("proof_command") or ""
    if "rch exec" not in proof_command:
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

log_path.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events))

report = {
    "accepted": not validation_errors,
    "artifact": str(artifact_path),
    "bead_id": artifact.get("bead_id", ""),
    "schema_version": artifact.get("schema_version"),
    "scenario_count": len(events),
    "accepted_count": accepted_count,
    "rejected_count": rejected_count,
    "malformed_count": malformed_count,
    "events_log": str(log_path),
    "validation_errors": validation_errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps(report, sort_keys=True))
raise SystemExit(0 if not validation_errors else 1)
PY

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
    cargo test -p asupersync --test slo_policy_bundle_contract --features test-internals -- --nocapture
  )
  printf '%q ' "${RCH_CMD[@]}" > "$RCH_LOG"
  printf '\n' >> "$RCH_LOG"
  set +e
  "${RCH_CMD[@]}" 2>&1 | tee -a "$RCH_LOG"
  rch_status=${PIPESTATUS[0]}
  set -e
  if grep -Eiq 'local fallback|fallback to local|executing locally' "$RCH_LOG"; then
    exit 86
  fi
  exit "$rch_status"
fi
