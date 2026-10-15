#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
CONTRACT_ARTIFACT="${PROJECT_ROOT}/artifacts/coordination_workload_bridge_signoff_v1.json"
OUTPUT_ROOT="${COORDINATION_WORKLOAD_BRIDGE_SIGNOFF_OUTPUT_DIR:-${PROJECT_ROOT}/target/coordination-workload-bridge-signoff}"
MODE="dry-run"
FIXTURE=0
RUN_ID="${COORDINATION_WORKLOAD_BRIDGE_SIGNOFF_RUN_ID:-coordination-workload-bridge-signoff-fixture}"
GENERATED_AT="${COORDINATION_WORKLOAD_BRIDGE_GENERATED_AT:-2026-05-05T05:00:00Z}"
EXTRA_REQUIRED_PATHS=()

usage() {
    cat <<'EOF'
Usage: ./scripts/run_coordination_workload_bridge_signoff.sh [options]

Modes:
  --list                      List signoff rows, outputs, and proof commands
  --dry-run                   Emit planned signoff rows without child execution
  --execute                   Execute the fixture-only final signoff
  --fixture                   Required for --execute

Options:
  --output-root <path>        Explicit artifact root for this signoff run
  --run-id <id>               Stable run id under output-root
  --generated-at <timestamp>  Stable timestamp passed to child fixture runs
  --extra-required-path <p>   Add a prerequisite path that must exist
  -h, --help                  Show this help text

The execute path never reads live Agent Mail, Beads, bv, rch, git, or home
directory state. It runs checked fixtures and records operator commands for the
human/agent closeout to run with br and bv.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            MODE="list"
            shift
            ;;
        --dry-run)
            MODE="dry-run"
            shift
            ;;
        --execute)
            MODE="execute"
            shift
            ;;
        --fixture)
            FIXTURE=1
            shift
            ;;
        --output-root)
            OUTPUT_ROOT="${2:-}"
            if [[ -z "$OUTPUT_ROOT" ]]; then
                echo "FATAL: --output-root requires a value" >&2
                exit 2
            fi
            shift 2
            ;;
        --run-id)
            RUN_ID="${2:-}"
            if [[ -z "$RUN_ID" ]]; then
                echo "FATAL: --run-id requires a value" >&2
                exit 2
            fi
            shift 2
            ;;
        --generated-at)
            GENERATED_AT="${2:-}"
            if [[ -z "$GENERATED_AT" ]]; then
                echo "FATAL: --generated-at requires a value" >&2
                exit 2
            fi
            shift 2
            ;;
        --extra-required-path)
            if [[ -z "${2:-}" ]]; then
                echo "FATAL: --extra-required-path requires a value" >&2
                exit 2
            fi
            EXTRA_REQUIRED_PATHS+=("$2")
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "FATAL: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

EXTRA_REQUIRED_PATHS_TEXT=""
if [[ "${#EXTRA_REQUIRED_PATHS[@]}" -gt 0 ]]; then
    EXTRA_REQUIRED_PATHS_TEXT="$(printf '%s\n' "${EXTRA_REQUIRED_PATHS[@]}")"
fi

SIGNOFF_PROJECT_ROOT="$PROJECT_ROOT" \
SIGNOFF_CONTRACT_ARTIFACT="$CONTRACT_ARTIFACT" \
SIGNOFF_OUTPUT_ROOT="$OUTPUT_ROOT" \
SIGNOFF_MODE="$MODE" \
SIGNOFF_FIXTURE="$FIXTURE" \
SIGNOFF_RUN_ID="$RUN_ID" \
SIGNOFF_GENERATED_AT="$GENERATED_AT" \
SIGNOFF_EXTRA_REQUIRED_PATHS="$EXTRA_REQUIRED_PATHS_TEXT" \
python3 - <<'PY'
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(os.environ["SIGNOFF_PROJECT_ROOT"])
CONTRACT_ARTIFACT = Path(os.environ["SIGNOFF_CONTRACT_ARTIFACT"])
OUTPUT_ROOT = Path(os.environ["SIGNOFF_OUTPUT_ROOT"])
MODE = os.environ["SIGNOFF_MODE"]
FIXTURE = os.environ["SIGNOFF_FIXTURE"] == "1"
RUN_ID = os.environ["SIGNOFF_RUN_ID"]
GENERATED_AT = os.environ["SIGNOFF_GENERATED_AT"]
EXTRA_REQUIRED_PATHS = [
    line for line in os.environ.get("SIGNOFF_EXTRA_REQUIRED_PATHS", "").splitlines() if line
]

REPORT_SCHEMA = "coordination-workload-bridge-signoff-report-v1"
ROW_SCHEMA = "coordination-workload-bridge-signoff-row-v1"
CONTRACT_VERSION = "coordination-workload-bridge-signoff-v1"

REQUIRED_TOOLS = ["bash", "jq", "python3", "sha256sum"]
REQUIRED_PATHS = [
    "artifacts/coordination_workload_bridge_signoff_v1.json",
    "artifacts/coordination_workload_bridge_smoke_contract_v1.json",
    "artifacts/agent_swarm_coordination_workload_contract_v1.json",
    "artifacts/agent_swarm_coordination_collector_contract_v1.json",
    "artifacts/agent_swarm_coordination_redaction_contract_v1.json",
    "artifacts/runtime_workload_corpus_v1.json",
    "artifacts/massive_swarm_signoff_smoke_contract_v1.json",
    "scripts/run_coordination_workload_bridge_smoke.sh",
    "scripts/run_agent_swarm_coordination_collector.sh",
    "scripts/run_runtime_workload_corpus.sh",
    "docs/coordination_workload_bridge_smoke_runbook.md",
    "tests/coordination_workload_bridge_smoke_contract.rs",
    "src/lab/replay.rs",
]

RUN_DIR = OUTPUT_ROOT / RUN_ID
LOG_DIR = RUN_DIR / "logs"
REPORT_PATH = RUN_DIR / "coordination-workload-bridge-signoff-report.json"
ROWS_JSONL = RUN_DIR / "coordination-workload-bridge-signoff.jsonl"
SUMMARY_PATH = RUN_DIR / "coordination-workload-bridge-signoff.summary.txt"
MANIFEST_PATH = RUN_DIR / "coordination-workload-bridge-signoff-manifest.json"
CHILD_MATRIX_PATH = RUN_DIR / "child-evidence-matrix.json"
FINGERPRINT_PATH = RUN_DIR / "fingerprint-comparison.json"
FIELD_MAP_PATH = RUN_DIR / "field-derivation-map.json"
FAIL_CLOSED_PATH = RUN_DIR / "fail-closed-diagnostics.json"
DEPENDENCY_BOUNDARY_PATH = RUN_DIR / "dependency-boundary.json"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def stable_hash(value):
    return "sha256:" + hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def resolve_artifact_path(value):
    path = Path(value)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def command_text(args):
    return " ".join(str(arg) for arg in args)


def row(
    *,
    row_id,
    consumer,
    phase,
    mode,
    expected_status,
    status,
    command="",
    exit_code=0,
    artifact_paths=None,
    first_failure_line="",
    stable_fingerprint=None,
    detail=None,
    log_path="",
):
    semantic = {
        "row_id": row_id,
        "consumer": consumer,
        "phase": phase,
        "expected_status": expected_status,
        "status": status,
        "first_failure_line": first_failure_line,
        "detail": detail or {},
    }
    return {
        "schema_version": ROW_SCHEMA,
        "row_id": row_id,
        "consumer": consumer,
        "phase": phase,
        "mode": mode,
        "expected_status": expected_status,
        "status": status,
        "command": command,
        "exit_code": exit_code,
        "artifact_paths": artifact_paths or {},
        "stable_fingerprint": stable_fingerprint or stable_hash(semantic),
        "first_failure_line": first_failure_line,
        "log_path": log_path,
        "detail": detail or {},
    }


def contract():
    if not CONTRACT_ARTIFACT.exists():
        print(f"FATAL: contract artifact missing at {CONTRACT_ARTIFACT}", file=sys.stderr)
        sys.exit(2)
    return load_json(CONTRACT_ARTIFACT)


def check_prerequisites():
    missing = []
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool) is None:
            missing.append(f"tool:{tool}")
    for path in REQUIRED_PATHS:
        if not (PROJECT_ROOT / path).exists():
            missing.append(path)
    for path in EXTRA_REQUIRED_PATHS:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = PROJECT_ROOT / candidate
        if not candidate.exists():
            missing.append(path)
    return sorted(missing)


def run_child(row_id, args, env=None):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / f"{row_id}.log"
    child_env = os.environ.copy()
    if env:
        child_env.update(env)
    completed = subprocess.run(
        [str(arg) for arg in args],
        cwd=PROJECT_ROOT,
        env=child_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    write_text(
        log_path,
        (
            f"$ {command_text(args)}\n"
            f"exit_code={completed.returncode}\n"
            "----- stdout -----\n"
            f"{completed.stdout}"
            "----- stderr -----\n"
            f"{completed.stderr}"
        ),
    )
    return completed, log_path


def rows_by_id(report):
    return {item["row_id"]: item for item in report["rows"]}


def report(rows, status, message, exit_code):
    passed = sum(1 for item in rows if item["status"] == "passed")
    fail_closed = sum(1 for item in rows if item["status"] == "fail_closed")
    dry_run = sum(1 for item in rows if item["status"] == "dry_run")
    unexpected = [
        item
        for item in rows
        if item["status"] != item["expected_status"] and item["status"] != "dry_run"
    ]
    payload = {
        "schema_version": REPORT_SCHEMA,
        "contract_version": CONTRACT_VERSION,
        "bead_id": "asupersync-qn8i0p.8",
        "runner_script": "scripts/run_coordination_workload_bridge_signoff.sh",
        "mode": MODE,
        "fixture": FIXTURE,
        "run_id": RUN_ID,
        "generated_at": GENERATED_AT,
        "output_root": str(OUTPUT_ROOT),
        "run_dir": str(RUN_DIR),
        "status": status,
        "message": message,
        "exit_code": exit_code,
        "live_inputs_used": False,
        "live_rch_used": False,
        "passed_row_count": passed,
        "fail_closed_row_count": fail_closed,
        "dry_run_row_count": dry_run,
        "unexpected_failure_count": len(unexpected),
        "unexpected_rows": [item["row_id"] for item in unexpected],
        "rows": rows,
        "artifact_paths": {
            "manifest": str(MANIFEST_PATH),
            "rows_jsonl": str(ROWS_JSONL),
            "report": str(REPORT_PATH),
            "summary": str(SUMMARY_PATH),
            "child_evidence_matrix": str(CHILD_MATRIX_PATH),
            "fingerprint_comparison": str(FINGERPRINT_PATH),
            "field_derivation_map": str(FIELD_MAP_PATH),
            "fail_closed_diagnostics": str(FAIL_CLOSED_PATH),
            "dependency_boundary": str(DEPENDENCY_BOUNDARY_PATH),
        },
        "validation_commands": contract()["validation"],
    }
    write_json(REPORT_PATH, payload)
    write_text(ROWS_JSONL, "".join(json.dumps(item, sort_keys=True) + "\n" for item in rows))
    write_text(
        SUMMARY_PATH,
        (
            f"coordination_workload_bridge_signoff run_id={RUN_ID} status={status} "
            f"passed={passed} fail_closed={fail_closed} dry_run={dry_run} "
            f"unexpected={len(unexpected)} report={REPORT_PATH}\n"
        ),
    )
    write_json(
        MANIFEST_PATH,
        {
            "schema_version": "coordination-workload-bridge-signoff-manifest-v1",
            "contract_version": CONTRACT_VERSION,
            "run_id": RUN_ID,
            "generated_at": GENERATED_AT,
            "mode": MODE,
            "fixture": FIXTURE,
            "row_count": len(rows),
            "report_path": str(REPORT_PATH),
            "rows_jsonl_path": str(ROWS_JSONL),
        },
    )
    print(SUMMARY_PATH.read_text(encoding="utf-8"), end="")
    for path in [
        MANIFEST_PATH,
        ROWS_JSONL,
        REPORT_PATH,
        SUMMARY_PATH,
        CHILD_MATRIX_PATH,
        FINGERPRINT_PATH,
        FIELD_MAP_PATH,
        FAIL_CLOSED_PATH,
        DEPENDENCY_BOUNDARY_PATH,
    ]:
        print(f"artifact {path}")
    return exit_code


def list_rows():
    data = contract()
    print("coordination-workload-bridge-signoff")
    print("modes list dry-run execute fixture output-root run-id generated-at")
    for output in data["artifact_outputs"]:
        print(f"output {output}")
    for item in data["signoff_rows"]:
        print(
            "row "
            f"{item['row_id']} phase={item['phase']} consumer={item['consumer']} "
            f"expected={item['expected_status']}"
        )
    for command in data["validation"]["rch_cargo"]:
        print(f"rch {command}")
    for command in data["validation"]["graph_state"]:
        print(f"graph {command}")
    return 0


def dry_run_rows():
    data = contract()
    planned = []
    for item in data["signoff_rows"]:
        planned.append(
            row(
                row_id=item["row_id"],
                consumer=item["consumer"],
                phase=item["phase"],
                mode="dry-run",
                expected_status="dry_run",
                status="dry_run",
                detail={
                    "planned": True,
                    "expected_execute_status": item["expected_status"],
                    "evidence": item["evidence"],
                },
            )
        )
    write_dry_run_artifacts(data, planned)
    return planned


def write_dry_run_artifacts(data, planned_rows):
    base = {
        "run_id": RUN_ID,
        "generated_at": GENERATED_AT,
        "mode": "dry-run",
        "execution_performed": False,
    }
    child_rows = []
    for child in data["child_evidence"]:
        paths = []
        for key in ["artifacts", "scripts", "docs", "tests"]:
            for item in child.get(key, []):
                paths.append({"path": item, "kind": key[:-1]})
        child_rows.append(
            {
                "bead_id": child["bead_id"],
                "expected_status": child["status"],
                "purpose": child["purpose"],
                "signoff_requirement": child["signoff_requirement"],
                "planned_paths": paths,
            }
        )
    write_json(
        CHILD_MATRIX_PATH,
        base
        | {
            "schema_version": "coordination-workload-bridge-child-evidence-matrix-dry-run-v1",
            "child_count": len(child_rows),
            "children": child_rows,
            "evaluation": "planned-only; child paths are not probed in dry-run mode",
        },
    )

    write_json(
        FINGERPRINT_PATH,
        base
        | {
            "schema_version": "coordination-workload-bridge-fingerprint-comparison-dry-run-v1",
            "planned_smoke_run_ids": ["stable-a", "stable-b"],
            "planned_row_count": len(planned_rows),
            "comparison_performed": False,
            "evaluation": "planned-only; bridge smoke scripts are not executed in dry-run mode",
        },
    )

    required_fields = data["field_derivation_contract"]["required_workload_fields"]
    required_workloads = data["field_derivation_contract"]["required_workload_count"]
    write_json(
        FIELD_MAP_PATH,
        base
        | {
            "schema_version": "coordination-workload-bridge-field-derivation-map-dry-run-v1",
            "required_workload_count": required_workloads,
            "required_field_count": len(required_fields),
            "required_fields": required_fields,
            "planned_row_count": required_workloads * len(required_fields),
            "evaluation": "planned-only; generated workload artifacts are not read in dry-run mode",
        },
    )

    write_json(
        FAIL_CLOSED_PATH,
        base
        | {
            "schema_version": "coordination-workload-bridge-fail-closed-diagnostics-dry-run-v1",
            "required_refusal_reasons": data["fail_closed_diagnostics"]["required_refusal_reasons"],
            "diagnostics_performed": False,
            "evaluation": "planned-only; malformed and stale fixture cases are not executed in dry-run mode",
        },
    )

    write_json(
        DEPENDENCY_BOUNDARY_PATH,
        base
        | {
            "schema_version": "coordination-workload-bridge-dependency-boundary-dry-run-v1",
            "forbidden_dependency_keys": data["core_runtime_dependency_boundary"]["forbidden_dependency_keys"],
            "policy_source": "artifacts/agent_swarm_coordination_workload_contract_v1.json",
            "scan_performed": False,
            "evaluation": "planned-only; Cargo dependency keys are not scanned in dry-run mode",
        },
    )


def verify_child_evidence():
    matrix = []
    missing = []
    for child in contract()["child_evidence"]:
        paths = []
        for key in ["artifacts", "scripts", "docs", "tests"]:
            for item in child.get(key, []):
                exists = (PROJECT_ROOT / item).exists()
                paths.append({"path": item, "kind": key[:-1], "exists": exists})
                if not exists:
                    missing.append(f"{child['bead_id']}:{item}")
        matrix.append(
            {
                "bead_id": child["bead_id"],
                "status": child["status"],
                "purpose": child["purpose"],
                "signoff_requirement": child["signoff_requirement"],
                "paths": paths,
                "closed": child["status"] == "closed",
            }
        )
        if child["status"] != "closed":
            missing.append(f"{child['bead_id']}:status={child['status']}")
    write_json(
        CHILD_MATRIX_PATH,
        {
            "schema_version": "coordination-workload-bridge-child-evidence-matrix-v1",
            "children": matrix,
            "missing": missing,
            "child_count": len(matrix),
        },
    )
    return missing


def run_smoke(run_id):
    root = RUN_DIR / "bridge-smoke"
    args = [
        "bash",
        PROJECT_ROOT / "scripts/run_coordination_workload_bridge_smoke.sh",
        "--execute",
        "--fixture",
        "--output-root",
        root,
        "--run-id",
        run_id,
        "--generated-at",
        GENERATED_AT,
    ]
    completed, log_path = run_child(f"bridge_smoke_{run_id}", args)
    report_path = root / run_id / "coordination-workload-bridge-smoke-report.json"
    if not report_path.exists():
        return completed, log_path, {}
    return completed, log_path, load_json(report_path)


def compare_smoke_fingerprints(first, second):
    first_rows = rows_by_id(first)
    second_rows = rows_by_id(second)
    comparison_rows = []
    all_equal = first.get("status") == "passed" and second.get("status") == "passed"
    all_equal = all_equal and first.get("unexpected_failure_count") == 0
    all_equal = all_equal and second.get("unexpected_failure_count") == 0
    all_equal = all_equal and set(first_rows) == set(second_rows)
    for row_id in sorted(set(first_rows) | set(second_rows)):
        first_row = first_rows.get(row_id, {})
        second_row = second_rows.get(row_id, {})
        equal = first_row.get("stable_fingerprint") == second_row.get("stable_fingerprint")
        status_equal = first_row.get("status") == second_row.get("status")
        all_equal = all_equal and equal and status_equal
        comparison_rows.append(
            {
                "row_id": row_id,
                "first_status": first_row.get("status"),
                "second_status": second_row.get("status"),
                "first_fingerprint": first_row.get("stable_fingerprint"),
                "second_fingerprint": second_row.get("stable_fingerprint"),
                "fingerprint_equal": equal,
                "status_equal": status_equal,
            }
        )
    payload = {
        "schema_version": "coordination-workload-bridge-fingerprint-comparison-v1",
        "first_run_id": first.get("run_id"),
        "second_run_id": second.get("run_id"),
        "first_status": first.get("status"),
        "second_status": second.get("status"),
        "first_passed_row_count": first.get("passed_row_count"),
        "second_passed_row_count": second.get("passed_row_count"),
        "first_fail_closed_row_count": first.get("fail_closed_row_count"),
        "second_fail_closed_row_count": second.get("fail_closed_row_count"),
        "row_count": len(comparison_rows),
        "all_equal": all_equal,
        "rows": comparison_rows,
    }
    write_json(FINGERPRINT_PATH, payload)
    return payload


def build_field_derivation_map(smoke_report):
    smoke_rows = rows_by_id(smoke_report)
    workload_row = smoke_rows["workload_expansion_accepts_collector_bundle"]
    collector_row = smoke_rows["collector_fixture_accepts_redacted_inputs"]
    pack = load_json(resolve_artifact_path(workload_row["artifact_paths"]["expansion_pack"]))
    collector_bundle = load_json(resolve_artifact_path(collector_row["artifact_paths"]["bundle"]))
    runtime_contract = load_json(PROJECT_ROOT / "artifacts/runtime_workload_corpus_v1.json")
    synthesis = runtime_contract["coordination_workload_synthesis"]
    mappings = {item["family"]: item for item in synthesis["scenario_family_mapping"]}
    events_by_family = {}
    for event in collector_bundle["events"]:
        if event.get("refusal_reason"):
            continue
        events_by_family.setdefault(event["workload_family"], []).append(event)

    required_fields = contract()["field_derivation_contract"]["required_workload_fields"]
    rows = []
    missing = []
    for workload in pack["workloads"]:
        scenario_family = workload["scenario_family"]
        mapping = mappings.get(scenario_family)
        events = sorted(events_by_family.get(scenario_family, []), key=lambda item: item["stable_sequence"])
        if mapping is None:
            missing.append(f"{workload['workload_id']}:mapping:{scenario_family}")
        if not events:
            missing.append(f"{workload['workload_id']}:events:{scenario_family}")
        event_kinds = sorted({event["event_kind"] for event in events})
        source_hashes = sorted(event["source_hash"] for event in events)
        expected = {
            "family": "agent-swarm-coordination",
            "scenario_family": scenario_family,
            "source_event_kinds": event_kinds,
            "source_event_count": len(events),
            "source_hashes": source_hashes,
            "source_bundle_hash": collector_bundle["source_bundle_hash"],
        }
        if mapping:
            for field in [
                "workload_id",
                "scenario_id",
                "runtime_profile",
                "semantic_pressure",
                "provenance_only_context",
                "replay_command",
                "entry_command",
                "expected_artifact_globs",
                "scheduler_evidence_input_id",
            ]:
                expected[field] = mapping[field]
        for field in required_fields:
            observed = workload.get(field)
            expected_value = expected.get(field)
            if observed != expected_value:
                missing.append(f"{workload['workload_id']}:{field}")
            if field in [
                "source_event_kinds",
                "source_event_count",
                "source_hashes",
                "source_bundle_hash",
            ]:
                source_evidence = "collector bundle accepted events grouped by workload_family"
                derivation = "derive from redacted source events after dedupe and deterministic sort"
            elif field in ["family", "scenario_family"]:
                source_evidence = "coordination workload synthesis contract"
                derivation = "constant agent-swarm family plus accepted event workload_family"
            else:
                source_evidence = (
                    "runtime_workload_corpus_v1.json::coordination_workload_synthesis."
                    f"scenario_family_mapping[{scenario_family}]"
                )
                derivation = "deterministic lookup by scenario_family"
            rows.append(
                {
                    "workload_id": workload["workload_id"],
                    "scenario_family": scenario_family,
                    "field": field,
                    "source_evidence": source_evidence,
                    "derivation_logic": derivation,
                    "observed_value_hash": stable_hash(observed),
                    "expected_value_hash": stable_hash(expected_value),
                    "status": "mapped" if observed == expected_value else "missing_or_mismatched",
                    "refusal_reason_if_missing": "missing_required_workload_field",
                }
            )
    payload = {
        "schema_version": "coordination-workload-bridge-field-derivation-map-v1",
        "pack_id": pack["pack_id"],
        "source_bundle_hash": pack["source_bundle_hash"],
        "workload_count": len(pack["workloads"]),
        "required_field_count": len(required_fields),
        "row_count": len(rows),
        "missing_or_mismatched": missing,
        "rows": rows,
    }
    write_json(FIELD_MAP_PATH, payload)
    return payload


def build_fail_closed_diagnostics(smoke_report):
    smoke_rows = rows_by_id(smoke_report)
    workload_contract = load_json(PROJECT_ROOT / "artifacts/agent_swarm_coordination_workload_contract_v1.json")
    reasons = set()
    diagnostics = []
    smoke_case_map = {
        "workload_expansion_refuses_missing_dimensions": "missing_scenario_dimensions",
        "collector_refuses_malformed_source_schema": "unknown_schema_version",
        "collector_refuses_unredacted_secret": "unredacted_secret",
        "dirty_frontier_unsupported_paths_fail_closed": "unsupported_dirty_paths",
        "schema_mismatch_guard_fails_closed": "schema_mismatch",
    }
    for row_id, reason in smoke_case_map.items():
        item = smoke_rows[row_id]
        if item["status"] == "fail_closed" and item.get("first_failure_line"):
            reasons.add(reason)
            diagnostics.append(
                {
                    "case": row_id,
                    "source": "coordination bridge smoke report",
                    "status": item["status"],
                    "refusal_reason": reason,
                    "first_failure_line": item["first_failure_line"],
                }
            )
    for sample in workload_contract["sample_bundles"]:
        for event in sample.get("events", []):
            reason = event.get("refusal_reason", "")
            if reason:
                reasons.add(reason)
                diagnostics.append(
                    {
                        "case": sample["sample_id"],
                        "source": "agent swarm coordination workload contract sample_bundles",
                        "status": "fail_closed",
                        "refusal_reason": reason,
                        "first_failure_line": reason,
                    }
                )
    required = set(contract()["fail_closed_diagnostics"]["required_refusal_reasons"])
    missing = sorted(required - reasons)
    payload = {
        "schema_version": "coordination-workload-bridge-fail-closed-diagnostics-v1",
        "required_refusal_reasons": sorted(required),
        "observed_refusal_reasons": sorted(reasons),
        "missing_refusal_reasons": missing,
        "diagnostics": diagnostics,
    }
    write_json(FAIL_CLOSED_PATH, payload)
    return payload


def dependency_keys_from_cargo():
    manifest = PROJECT_ROOT / "Cargo.toml"
    keys = []
    section = ""
    for raw in manifest.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]")
            continue
        if "=" not in line:
            continue
        if "dependencies" not in section:
            continue
        if "dev-dependencies" in section or "build-dependencies" in section:
            continue
        key = line.split("=", 1)[0].strip().strip('"').strip("'")
        if key:
            package_name = ""
            if "package" in line:
                for quote in ['"', "'"]:
                    marker = f"package = {quote}"
                    if marker in line:
                        package_name = line.split(marker, 1)[1].split(quote, 1)[0]
                        break
            keys.append({"section": section, "key": key, "package": package_name})
    return keys


def build_dependency_boundary():
    workload_contract = load_json(PROJECT_ROOT / "artifacts/agent_swarm_coordination_workload_contract_v1.json")
    policy = workload_contract["core_runtime_dependency_policy"]
    forbidden = set(contract()["core_runtime_dependency_boundary"]["forbidden_dependency_keys"])
    keys = dependency_keys_from_cargo()
    violations = [
        item for item in keys if item["key"] in forbidden or item.get("package") in forbidden
    ]
    payload = {
        "schema_version": "coordination-workload-bridge-dependency-boundary-v1",
        "policy": policy,
        "dependency_key_count": len(keys),
        "forbidden_dependency_keys": sorted(forbidden),
        "violations": violations,
        "comments_and_operator_commands_ignored": True,
    }
    write_json(DEPENDENCY_BOUNDARY_PATH, payload)
    return payload


def verify_planner_handoff():
    massive = load_json(PROJECT_ROOT / "artifacts/massive_swarm_signoff_smoke_contract_v1.json")
    rows = [
        item
        for item in massive["signoff_matrix"]
        if item["control_id"] == "coordination_workload_planner_handoff"
    ]
    if not rows:
        return False, {}
    item = rows[0]
    required = {
        "AA-COORDINATION-WORKLOAD-PLANNER-HANDOFF-USED",
        "AA-COORDINATION-WORKLOAD-PLANNER-HANDOFF-REFUSED",
        "AA-COORDINATION-WORKLOAD-PLANNER-HANDOFF-ABSENT",
    }
    present = set(item["scenario_ids"])
    ok = (
        item["tracker_status"] == "closed"
        and item["proof_status"] == "trusted"
        and required.issubset(present)
        and "conservative_baseline" in item["fallback_mode"]
    )
    return ok, item


def execute_rows():
    if not FIXTURE:
        failure = row(
            row_id="unsupported_live_input_guard",
            consumer="operator",
            phase="admission",
            mode="execute",
            expected_status="passed",
            status="fail_closed",
            first_failure_line="execute requires --fixture; live Agent Mail, Beads, bv, rch, git, and home reads are unsupported",
            detail={"live_inputs_used": False},
        )
        return [failure], "failed", "execute refused unsupported live-input mode", 2

    rows = []
    missing = check_prerequisites()
    if missing:
        rows.append(
            row(
                row_id="missing_prerequisite_guard",
                consumer="operator",
                phase="admission",
                mode="execute",
                expected_status="passed",
                status="fail_closed",
                first_failure_line="missing prerequisites: " + ",".join(missing),
                detail={"missing": missing},
            )
        )
        return rows, "failed", "missing prerequisite guard failed closed", 2

    rows.append(
        row(
            row_id="missing_prerequisite_guard",
            consumer="operator",
            phase="admission",
            mode="execute",
            expected_status="passed",
            status="passed",
            detail={"checked_tools": REQUIRED_TOOLS, "checked_paths": REQUIRED_PATHS},
        )
    )

    child_missing = verify_child_evidence()
    rows.append(
        row(
            row_id="child_evidence_matrix_complete",
            consumer="operator",
            phase="child-aggregation",
            mode="execute",
            expected_status="passed",
            status="passed" if not child_missing else "failed",
            first_failure_line="" if not child_missing else "missing child evidence: " + ",".join(child_missing),
            artifact_paths={"child_evidence_matrix": str(CHILD_MATRIX_PATH)},
            detail={"missing": child_missing, "child_count": len(contract()["child_evidence"])},
        )
    )

    first_completed, first_log, first_report = run_smoke("stable-a")
    second_completed, second_log, second_report = run_smoke("stable-b")
    comparison = compare_smoke_fingerprints(first_report, second_report)
    fingerprints_ok = first_completed.returncode == 0 and second_completed.returncode == 0
    fingerprints_ok = fingerprints_ok and comparison["all_equal"]
    rows.append(
        row(
            row_id="repeated_fixture_fingerprints_identical",
            consumer="bridge-smoke",
            phase="determinism",
            mode="execute",
            expected_status="passed",
            status="passed" if fingerprints_ok else "failed",
            command="; ".join([
                "bash scripts/run_coordination_workload_bridge_smoke.sh --execute --fixture --run-id stable-a",
                "bash scripts/run_coordination_workload_bridge_smoke.sh --execute --fixture --run-id stable-b",
            ]),
            exit_code=0 if fingerprints_ok else 1,
            artifact_paths={
                "fingerprint_comparison": str(FINGERPRINT_PATH),
                "first_report": first_report.get("artifact_paths", {}).get("report", ""),
                "second_report": second_report.get("artifact_paths", {}).get("report", ""),
            },
            first_failure_line="" if fingerprints_ok else "bridge smoke fingerprints or statuses drifted",
            stable_fingerprint=stable_hash(comparison),
            detail={
                "all_equal": comparison["all_equal"],
                "row_count": comparison["row_count"],
                "first_passed_row_count": comparison["first_passed_row_count"],
                "first_fail_closed_row_count": comparison["first_fail_closed_row_count"],
                "second_passed_row_count": comparison["second_passed_row_count"],
                "second_fail_closed_row_count": comparison["second_fail_closed_row_count"],
            },
            log_path=f"{first_log},{second_log}",
        )
    )

    field_map = build_field_derivation_map(first_report)
    fields_ok = (
        field_map["workload_count"] == contract()["field_derivation_contract"]["required_workload_count"]
        and not field_map["missing_or_mismatched"]
    )
    rows.append(
        row(
            row_id="field_derivation_map_covers_generated_workloads",
            consumer="runtime-workload",
            phase="field-derivation",
            mode="execute",
            expected_status="passed",
            status="passed" if fields_ok else "failed",
            artifact_paths={"field_derivation_map": str(FIELD_MAP_PATH)},
            first_failure_line="" if fields_ok else "missing or mismatched workload fields",
            stable_fingerprint=stable_hash(
                {
                    "source_bundle_hash": field_map["source_bundle_hash"],
                    "workload_count": field_map["workload_count"],
                    "required_field_count": field_map["required_field_count"],
                    "row_count": field_map["row_count"],
                    "missing_or_mismatched": field_map["missing_or_mismatched"],
                }
            ),
            detail={
                "workload_count": field_map["workload_count"],
                "required_field_count": field_map["required_field_count"],
                "row_count": field_map["row_count"],
                "missing_or_mismatched": field_map["missing_or_mismatched"],
            },
        )
    )

    fail_closed = build_fail_closed_diagnostics(first_report)
    fail_closed_ok = not fail_closed["missing_refusal_reasons"]
    rows.append(
        row(
            row_id="fail_closed_diagnostics_cover_malformed_stale_secret_unsupported",
            consumer="redaction",
            phase="fail-closed",
            mode="execute",
            expected_status="passed",
            status="passed" if fail_closed_ok else "failed",
            artifact_paths={"fail_closed_diagnostics": str(FAIL_CLOSED_PATH)},
            first_failure_line="" if fail_closed_ok else "missing refusal reasons: " + ",".join(fail_closed["missing_refusal_reasons"]),
            stable_fingerprint=stable_hash(
                {
                    "observed": fail_closed["observed_refusal_reasons"],
                    "missing": fail_closed["missing_refusal_reasons"],
                }
            ),
            detail={
                "observed_refusal_reasons": fail_closed["observed_refusal_reasons"],
                "missing_refusal_reasons": fail_closed["missing_refusal_reasons"],
            },
        )
    )

    dependency_boundary = build_dependency_boundary()
    dependency_ok = not dependency_boundary["violations"]
    rows.append(
        row(
            row_id="core_runtime_dependency_boundary_enforced",
            consumer="runtime-core",
            phase="dependency-boundary",
            mode="execute",
            expected_status="passed",
            status="passed" if dependency_ok else "failed",
            artifact_paths={"dependency_boundary": str(DEPENDENCY_BOUNDARY_PATH)},
            first_failure_line="" if dependency_ok else "forbidden core dependency keys present",
            stable_fingerprint=stable_hash(
                {
                    "forbidden_dependency_keys": dependency_boundary["forbidden_dependency_keys"],
                    "violations": dependency_boundary["violations"],
                }
            ),
            detail={
                "dependency_key_count": dependency_boundary["dependency_key_count"],
                "forbidden_dependency_keys": dependency_boundary["forbidden_dependency_keys"],
                "violations": dependency_boundary["violations"],
            },
        )
    )

    planner_ok, planner = verify_planner_handoff()
    rows.append(
        row(
            row_id="planner_capacity_profile_handoff_confirmed",
            consumer="capacity-profile",
            phase="planner-handoff",
            mode="execute",
            expected_status="passed",
            status="passed" if planner_ok else "failed",
            first_failure_line="" if planner_ok else "coordination planner handoff missing or not trusted",
            stable_fingerprint=stable_hash(
                {
                    "tracker_status": planner.get("tracker_status"),
                    "proof_status": planner.get("proof_status"),
                    "scenario_ids": planner.get("scenario_ids"),
                    "fallback_mode": planner.get("fallback_mode"),
                }
            ),
            detail=planner,
        )
    )

    commands = contract()["validation"]
    command_ok = bool(commands["rch_cargo"]) and bool(commands["graph_state"])
    rows.append(
        row(
            row_id="graph_state_and_rch_validation_commands_documented",
            consumer="operator",
            phase="operator-closeout",
            mode="execute",
            expected_status="passed",
            status="passed" if command_ok else "failed",
            first_failure_line="" if command_ok else "validation commands missing",
            stable_fingerprint=stable_hash(commands),
            detail={
                "live_graph_state_used_by_runner": False,
                "local_shell": commands["local_shell"],
                "rch_cargo": commands["rch_cargo"],
                "graph_state": commands["graph_state"],
            },
        )
    )

    unexpected = [item for item in rows if item["status"] != item["expected_status"]]
    if unexpected:
        return rows, "failed", "one or more signoff rows failed", 1
    return rows, "passed", "coordination workload bridge signoff passed", 0


if MODE == "list":
    sys.exit(list_rows())

if MODE == "dry-run":
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    rows = dry_run_rows()
    sys.exit(report(rows, "dry_run", "planned coordination workload bridge signoff", 0))

if MODE == "execute":
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    rows, status, message, exit_code = execute_rows()
    sys.exit(report(rows, status, message, exit_code))

print(f"FATAL: unknown mode {MODE}", file=sys.stderr)
sys.exit(2)
PY
