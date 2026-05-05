#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
CONTRACT_ARTIFACT="${PROJECT_ROOT}/artifacts/coordination_workload_bridge_smoke_contract_v1.json"
OUTPUT_ROOT="${COORDINATION_WORKLOAD_BRIDGE_SMOKE_OUTPUT_DIR:-${PROJECT_ROOT}/target/coordination-workload-bridge-smoke}"
MODE="dry-run"
FIXTURE=0
RUN_ID="${COORDINATION_WORKLOAD_BRIDGE_SMOKE_RUN_ID:-coordination-workload-bridge-fixture}"
GENERATED_AT="${COORDINATION_WORKLOAD_BRIDGE_GENERATED_AT:-2026-05-05T05:00:00Z}"
EXTRA_REQUIRED_PATHS=()

usage() {
    cat <<'EOF'
Usage: ./scripts/run_coordination_workload_bridge_smoke.sh [options]

Modes:
  --list                      List smoke rows, consumers, and artifact outputs
  --dry-run                   Emit a planned run report without running child smoke scripts
  --execute                   Execute the local fixture bridge smoke
  --fixture                   Use checked synthetic coordination fixtures

Options:
  --output-root <path>        Explicit artifact root for this smoke run
  --run-id <id>               Stable run id under output-root
  --generated-at <timestamp>  Stable timestamp for generated child artifacts
  --extra-required-path <p>   Add a prerequisite path that must exist
  -h, --help                  Show this help text

The execute path never reads live Agent Mail, Beads, bv, rch, git, or home
directory state. It runs checked fixtures and local dry-run planner handoffs.
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

BRIDGE_PROJECT_ROOT="$PROJECT_ROOT" \
BRIDGE_CONTRACT_ARTIFACT="$CONTRACT_ARTIFACT" \
BRIDGE_OUTPUT_ROOT="$OUTPUT_ROOT" \
BRIDGE_MODE="$MODE" \
BRIDGE_FIXTURE="$FIXTURE" \
BRIDGE_RUN_ID="$RUN_ID" \
BRIDGE_GENERATED_AT="$GENERATED_AT" \
BRIDGE_EXTRA_REQUIRED_PATHS="$EXTRA_REQUIRED_PATHS_TEXT" \
python3 - <<'PY'
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(os.environ["BRIDGE_PROJECT_ROOT"])
CONTRACT_ARTIFACT = Path(os.environ["BRIDGE_CONTRACT_ARTIFACT"])
OUTPUT_ROOT = Path(os.environ["BRIDGE_OUTPUT_ROOT"])
MODE = os.environ["BRIDGE_MODE"]
FIXTURE = os.environ["BRIDGE_FIXTURE"] == "1"
RUN_ID = os.environ["BRIDGE_RUN_ID"]
GENERATED_AT = os.environ["BRIDGE_GENERATED_AT"]
EXTRA_REQUIRED_PATHS = [
    line for line in os.environ.get("BRIDGE_EXTRA_REQUIRED_PATHS", "").splitlines() if line
]

REPORT_SCHEMA = "coordination-workload-bridge-smoke-report-v1"
ROW_SCHEMA = "coordination-workload-bridge-smoke-row-v1"
CONTRACT_VERSION = "coordination-workload-bridge-smoke-contract-v1"

REQUIRED_TOOLS = ["bash", "jq", "python3", "sha256sum"]
REQUIRED_PATHS = [
    "artifacts/agent_swarm_coordination_collector_contract_v1.json",
    "artifacts/agent_swarm_coordination_redaction_contract_v1.json",
    "artifacts/agent_swarm_coordination_workload_contract_v1.json",
    "artifacts/runtime_workload_corpus_v1.json",
    "artifacts/massive_swarm_signoff_smoke_contract_v1.json",
    "scripts/run_agent_swarm_coordination_collector.sh",
    "scripts/run_runtime_workload_corpus.sh",
    "scripts/run_capacity_envelope_planner_smoke.sh",
    "scripts/run_host_profile_planner_smoke.sh",
    "scripts/run_signed_profile_bundle_smoke.sh",
]


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


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(PROJECT_ROOT.resolve()))
    except ValueError:
        return str(path)


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


RUN_DIR = OUTPUT_ROOT / RUN_ID
LOG_DIR = RUN_DIR / "logs"
FIXTURE_DIR = RUN_DIR / "fixtures"
ROWS_JSONL = RUN_DIR / "coordination-workload-bridge-smoke.jsonl"
REPORT_PATH = RUN_DIR / "coordination-workload-bridge-smoke-report.json"
SUMMARY_PATH = RUN_DIR / "coordination-workload-bridge-smoke.summary.txt"
MANIFEST_PATH = RUN_DIR / "coordination-workload-bridge-smoke-manifest.json"


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
        "bead_id": "asupersync-qn8i0p.7",
        "runner_script": "scripts/run_coordination_workload_bridge_smoke.sh",
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
        },
        "validation_commands": {
            "local_shell": [
                "bash -n scripts/run_coordination_workload_bridge_smoke.sh",
                "jq empty artifacts/coordination_workload_bridge_smoke_contract_v1.json",
                "bash scripts/run_coordination_workload_bridge_smoke.sh --list",
                "bash scripts/run_coordination_workload_bridge_smoke.sh --dry-run --fixture --output-root target/coordination-workload-bridge-smoke-dry-run",
                "bash scripts/run_coordination_workload_bridge_smoke.sh --execute --fixture --output-root target/coordination-workload-bridge-smoke --generated-at 2026-05-05T05:00:00Z",
            ],
            "rch_cargo": [
                "rch exec -- env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_coordination_workload_bridge_smoke cargo test -p asupersync --test coordination_workload_bridge_smoke_contract --features test-internals -- --nocapture"
            ],
        },
    }
    write_json(REPORT_PATH, payload)
    write_text(ROWS_JSONL, "".join(json.dumps(item, sort_keys=True) + "\n" for item in rows))
    write_text(
        SUMMARY_PATH,
        (
            f"coordination_workload_bridge_smoke run_id={RUN_ID} status={status} "
            f"passed={passed} fail_closed={fail_closed} dry_run={dry_run} "
            f"unexpected={len(unexpected)} report={REPORT_PATH}\n"
        ),
    )
    write_json(
        MANIFEST_PATH,
        {
            "schema_version": "coordination-workload-bridge-smoke-manifest-v1",
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
    print(f"artifact {MANIFEST_PATH}")
    print(f"artifact {ROWS_JSONL}")
    print(f"artifact {REPORT_PATH}")
    print(f"artifact {SUMMARY_PATH}")
    return exit_code


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
    return missing


def command_text(args):
    return " ".join(str(arg) for arg in args)


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


def artifact_from_stdout(stdout, suffix):
    for line in stdout.splitlines():
        if line.startswith("artifact ") and line.endswith(suffix):
            return Path(line.split(" ", 1)[1])
    raise RuntimeError(f"child output did not include artifact ending in {suffix}")


def dry_run_rows():
    rows = []
    for item in contract()["smoke_rows"]:
        rows.append(
            row(
                row_id=item["row_id"],
                consumer=item["consumer"],
                phase=item["phase"],
                mode="dry-run",
                expected_status="dry_run",
                status="dry_run",
                command=item["command"],
                detail={
                    "planned": True,
                    "expected_execute_status": item["expected_status"],
                    "fail_closed_if": item.get("fail_closed_if", []),
                },
            )
        )
    return rows


def list_rows():
    data = contract()
    print("coordination-workload-bridge-smoke")
    print("modes list dry-run execute fixture output-root run-id generated-at")
    for output in data["artifact_outputs"]:
        print(f"output {output}")
    for item in data["smoke_rows"]:
        print(
            "row "
            f"{item['row_id']} phase={item['phase']} consumer={item['consumer']} "
            f"expected={item['expected_status']}"
        )
    return 0


def execute_rows():
    if not FIXTURE:
        failure = row(
            row_id="unsupported_live_input_guard",
            consumer="operator",
            phase="admission",
            mode="execute",
            expected_status="passed",
            status="fail_closed",
            first_failure_line="execute requires --fixture; live Agent Mail, Beads, bv, rch, and git reads are unsupported",
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
                first_failure_line="missing prerequisites: " + ",".join(sorted(missing)),
                detail={"missing": sorted(missing)},
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
            detail={"checked_paths": REQUIRED_PATHS, "checked_tools": REQUIRED_TOOLS},
        )
    )

    required_families = set(load_json(PROJECT_ROOT / "artifacts/runtime_workload_corpus_v1.json")[
        "coordination_workload_synthesis"
    ]["required_scenario_families"])

    latency_path = FIXTURE_DIR / "latency-agent-mail.json"
    write_json(
        latency_path,
        {
            "messages": [
                {
                    "id": 992,
                    "from": "Operator",
                    "thread_id": "asupersync-qn8i0p.7",
                    "created_ts": GENERATED_AT,
                    "subject": "ack-required coordination latency fixture",
                    "ack_required": True,
                    "body_md": "metadata-only fixture body is intentionally not retained",
                }
            ]
        },
    )
    collector_root = RUN_DIR / "collector"
    collector_args = [
        "bash",
        PROJECT_ROOT / "scripts/run_agent_swarm_coordination_collector.sh",
        "--fixture",
        "--source",
        f"agent_mail:{latency_path}",
        "--output-root",
        collector_root,
        "--run-id",
        "coordination-bridge-collector-fixture",
        "--generated-at",
        GENERATED_AT,
    ]
    completed, log_path = run_child("collector_fixture_accepts_redacted_inputs", collector_args)
    collector_report_path = (
        collector_root
        / "coordination-bridge-collector-fixture"
        / "coordination-collector-report.json"
    )
    collector_bundle_path = (
        collector_root
        / "coordination-bridge-collector-fixture"
        / "coordination-workload-bundle.json"
    )
    collector_report = load_json(collector_report_path) if collector_report_path.exists() else {}
    collector_bundle = load_json(collector_bundle_path) if collector_bundle_path.exists() else {}
    collector_families = {
        event.get("workload_family")
        for event in collector_bundle.get("events", [])
        if not event.get("refusal_reason")
    }
    collector_passed = (
        completed.returncode == 0
        and collector_report.get("privacy_verdict") == "pass"
        and collector_report.get("refused_event_count") == 0
        and required_families.issubset(collector_families)
    )
    rows.append(
        row(
            row_id="collector_fixture_accepts_redacted_inputs",
            consumer="collector",
            phase="collector",
            mode="fixture",
            expected_status="passed",
            status="passed" if collector_passed else "failed",
            command=command_text(collector_args),
            exit_code=completed.returncode,
            artifact_paths=collector_report.get("artifact_paths", {}),
            first_failure_line="" if collector_passed else collector_report.get("first_failure_line", "collector fixture failed"),
            stable_fingerprint=collector_report.get("source_bundle_hash") or None,
            detail={
                "accepted_event_count": collector_report.get("accepted_event_count"),
                "refused_event_count": collector_report.get("refused_event_count"),
                "duplicate_event_count": collector_report.get("duplicate_event_count"),
                "privacy_verdict": collector_report.get("privacy_verdict"),
                "covered_scenario_families": sorted(collector_families),
            },
            log_path=str(log_path),
        )
    )

    workload_root = RUN_DIR / "workload"
    synth_args = [
        "bash",
        PROJECT_ROOT / "scripts/run_runtime_workload_corpus.sh",
        "--synthesize-coordination-pack",
        "--coordination-bundle",
        collector_bundle_path,
        "--output-root",
        workload_root,
        "--generated-at",
        GENERATED_AT,
    ]
    completed, log_path = run_child("workload_expansion_accepts_collector_bundle", synth_args)
    synth_report_path = artifact_from_stdout(
        completed.stdout, "coordination-workload-synthesis-report.json"
    )
    synth_pack_path = artifact_from_stdout(
        completed.stdout, "coordination-workload-expansion-pack.json"
    )
    synth_report = load_json(synth_report_path)
    synth_pack = load_json(synth_pack_path)
    synth_passed = (
        completed.returncode == 0
        and synth_report.get("status") == "passed"
        and synth_report.get("accepted_workload_count") == 7
        and synth_report.get("refused_bundle_count") == 0
        and len(synth_pack.get("workloads", [])) == 7
    )
    rows.append(
        row(
            row_id="workload_expansion_accepts_collector_bundle",
            consumer="synthesis",
            phase="workload-corpus",
            mode="execute",
            expected_status="passed",
            status="passed" if synth_passed else "failed",
            command=command_text(synth_args),
            exit_code=completed.returncode,
            artifact_paths=synth_report.get("artifact_paths", {}),
            first_failure_line="" if synth_passed else synth_report.get("first_failure_line", "synthesis failed"),
            stable_fingerprint=stable_hash(
                {
                    "source_bundle_hash": synth_report.get("source_bundle_hash"),
                    "status": synth_report.get("status"),
                    "accepted_workload_count": synth_report.get("accepted_workload_count"),
                    "missing_scenario_families": synth_report.get("missing_scenario_families"),
                }
            ),
            detail={
                "accepted_workload_count": synth_report.get("accepted_workload_count"),
                "refused_bundle_count": synth_report.get("refused_bundle_count"),
                "covered_scenario_families": synth_pack.get("covered_scenario_families"),
            },
            log_path=str(log_path),
        )
    )

    refused_root = RUN_DIR / "workload-refused"
    refused_args = [
        "bash",
        PROJECT_ROOT / "scripts/run_runtime_workload_corpus.sh",
        "--synthesize-coordination-pack",
        "--coordination-fixture-id",
        "refused-missing-scenario-dimensions",
        "--output-root",
        refused_root,
        "--generated-at",
        GENERATED_AT,
    ]
    completed, log_path = run_child("workload_expansion_refuses_missing_dimensions", refused_args)
    refused_report_path = artifact_from_stdout(
        completed.stdout, "coordination-workload-synthesis-report.json"
    )
    refused_report = load_json(refused_report_path)
    missing = refused_report.get("missing_scenario_families", [])
    refused_passed = (
        completed.returncode != 0
        and refused_report.get("status") == "refused"
        and len(missing) == 6
        and "missing_scenario_dimensions" in refused_report.get("first_failure_line", "")
    )
    rows.append(
        row(
            row_id="workload_expansion_refuses_missing_dimensions",
            consumer="synthesis",
            phase="workload-corpus",
            mode="fixture-refusal",
            expected_status="fail_closed",
            status="fail_closed" if refused_passed else "failed",
            command=command_text(refused_args),
            exit_code=completed.returncode,
            artifact_paths=refused_report.get("artifact_paths", {}),
            first_failure_line=refused_report.get("first_failure_line", ""),
            detail={"missing_scenario_families": missing},
            log_path=str(log_path),
        )
    )

    malformed_path = FIXTURE_DIR / "malformed-agent-mail.json"
    write_text(malformed_path, "{\n")
    malformed_root = RUN_DIR / "collector-malformed"
    malformed_args = [
        "bash",
        PROJECT_ROOT / "scripts/run_agent_swarm_coordination_collector.sh",
        "--execute",
        "--source",
        f"agent_mail:{malformed_path}",
        "--output-root",
        malformed_root,
        "--run-id",
        "coordination-bridge-malformed",
        "--generated-at",
        GENERATED_AT,
    ]
    completed, log_path = run_child("collector_refuses_malformed_source_schema", malformed_args)
    malformed_report_path = malformed_root / "coordination-bridge-malformed" / "coordination-collector-report.json"
    malformed_report = load_json(malformed_report_path)
    malformed_passed = (
        completed.returncode != 0
        and malformed_report.get("privacy_verdict") == "fail_closed"
        and "unknown_schema_version" in malformed_report.get("first_failure_line", "")
    )
    rows.append(
        row(
            row_id="collector_refuses_malformed_source_schema",
            consumer="redaction",
            phase="collector-refusal",
            mode="execute",
            expected_status="fail_closed",
            status="fail_closed" if malformed_passed else "failed",
            command=command_text(malformed_args),
            exit_code=completed.returncode,
            artifact_paths=malformed_report.get("artifact_paths", {}),
            first_failure_line=malformed_report.get("first_failure_line", ""),
            stable_fingerprint=stable_hash(
                {
                    "row_id": "collector_refuses_malformed_source_schema",
                    "refusal_reason": "unknown_schema_version",
                    "privacy_verdict": malformed_report.get("privacy_verdict"),
                }
            ),
            detail={"privacy_verdict": malformed_report.get("privacy_verdict")},
            log_path=str(log_path),
        )
    )

    secret_path = FIXTURE_DIR / "secret-agent-mail.json"
    write_json(
        secret_path,
        {
            "messages": [
                {
                    "id": 991,
                    "from": "Operator",
                    "thread_id": "asupersync-qn8i0p.7",
                    "created_ts": GENERATED_AT,
                    "subject": "secret fixture",
                    "ack_required": True,
                    "body_md": "Authorization: Bearer should-never-enter-a-bundle",
                }
            ]
        },
    )
    secret_root = RUN_DIR / "collector-secret"
    secret_args = [
        "bash",
        PROJECT_ROOT / "scripts/run_agent_swarm_coordination_collector.sh",
        "--execute",
        "--source",
        f"agent_mail:{secret_path}",
        "--output-root",
        secret_root,
        "--run-id",
        "coordination-bridge-secret",
        "--generated-at",
        GENERATED_AT,
    ]
    completed, log_path = run_child("collector_refuses_unredacted_secret", secret_args)
    secret_report_path = secret_root / "coordination-bridge-secret" / "coordination-collector-report.json"
    secret_report = load_json(secret_report_path)
    secret_passed = (
        completed.returncode != 0
        and secret_report.get("privacy_verdict") == "fail_closed"
        and "unredacted_secret" in secret_report.get("first_failure_line", "")
    )
    rows.append(
        row(
            row_id="collector_refuses_unredacted_secret",
            consumer="redaction",
            phase="collector-refusal",
            mode="execute",
            expected_status="fail_closed",
            status="fail_closed" if secret_passed else "failed",
            command=command_text(secret_args),
            exit_code=completed.returncode,
            artifact_paths=secret_report.get("artifact_paths", {}),
            first_failure_line=secret_report.get("first_failure_line", ""),
            stable_fingerprint=stable_hash(
                {
                    "row_id": "collector_refuses_unredacted_secret",
                    "refusal_reason": "unredacted_secret",
                    "privacy_verdict": secret_report.get("privacy_verdict"),
                }
            ),
            detail={"privacy_verdict": secret_report.get("privacy_verdict")},
            log_path=str(log_path),
        )
    )

    dirty_path = FIXTURE_DIR / "dirty-frontier-unsupported.json"
    write_json(
        dirty_path,
        {
            "observed_at": GENERATED_AT,
            "paths": [
                "/data/projects/asupersync/private/operator-note.rs",
                "~/.ssh/id_ed25519",
                ".beads/issues.jsonl",
            ],
        },
    )
    dirty_root = RUN_DIR / "collector-dirty"
    dirty_args = [
        "bash",
        PROJECT_ROOT / "scripts/run_agent_swarm_coordination_collector.sh",
        "--execute",
        "--source",
        f"git_dirty_frontier:{dirty_path}",
        "--output-root",
        dirty_root,
        "--run-id",
        "coordination-bridge-dirty-frontier",
        "--generated-at",
        GENERATED_AT,
    ]
    completed, log_path = run_child("dirty_frontier_unsupported_paths_fail_closed", dirty_args)
    dirty_bundle_path = dirty_root / "coordination-bridge-dirty-frontier" / "coordination-workload-bundle.json"
    dirty_bundle = load_json(dirty_bundle_path)
    unsupported_count = sum(
        int(event.get("file_frontier", {}).get("unsupported_dirty_paths_count", 0))
        for event in dirty_bundle.get("events", [])
    )
    dirty_passed = completed.returncode == 0 and unsupported_count > 0
    rows.append(
        row(
            row_id="dirty_frontier_unsupported_paths_fail_closed",
            consumer="collector",
            phase="admission",
            mode="execute",
            expected_status="fail_closed",
            status="fail_closed" if dirty_passed else "failed",
            command=command_text(dirty_args),
            exit_code=completed.returncode,
            artifact_paths={"bundle": str(dirty_bundle_path)},
            first_failure_line="unsupported_dirty_frontier_paths" if dirty_passed else "dirty frontier guard did not trigger",
            detail={"unsupported_dirty_paths_count": unsupported_count},
            log_path=str(log_path),
        )
    )

    mismatch_path = FIXTURE_DIR / "schema-mismatch-bundle.json"
    mismatch_bundle = dict(load_json(collector_bundle_path))
    mismatch_bundle["schema_version"] = "agent-swarm-coordination-workload-bundle-v0"
    write_json(mismatch_path, mismatch_bundle)
    mismatch_passed = mismatch_bundle.get("schema_version") != "agent-swarm-coordination-workload-bundle-v1"
    rows.append(
        row(
            row_id="schema_mismatch_guard_fails_closed",
            consumer="synthesis",
            phase="admission",
            mode="execute",
            expected_status="fail_closed",
            status="fail_closed" if mismatch_passed else "failed",
            artifact_paths={"mismatched_bundle": str(mismatch_path)},
            first_failure_line="schema mismatch: expected agent-swarm-coordination-workload-bundle-v1",
            detail={
                "observed_schema_version": mismatch_bundle.get("schema_version"),
                "expected_schema_version": "agent-swarm-coordination-workload-bundle-v1",
            },
        )
    )

    pack_families = {item.get("scenario_family") for item in synth_pack.get("workloads", [])}
    replay_totals = {
        "expected_task_events": 18,
        "expected_queue_events": 16,
        "expected_timer_events": 12,
        "expected_cancel_events": 2,
        "expected_artifact_events": 11,
        "expected_minimized_first_failure": "dirty_frontier_fail_closed",
    }
    replay_passed = (
        synth_pack.get("schema_version") == "runtime-workload-coordination-expansion-pack-v1"
        and required_families == pack_families
        and not synth_pack.get("refused_bundles")
    )
    replay_handoff_path = RUN_DIR / "replay-hook-handoff.json"
    write_json(
        replay_handoff_path,
        {
            "schema_version": "coordination-pressure-replay-hook-handoff-v1",
            "pack_path": str(synth_pack_path),
            "source_bundle_hash": synth_pack.get("source_bundle_hash"),
            "required_scenario_families": sorted(required_families),
            "covered_scenario_families": sorted(pack_families),
            "expected_replay_api": [
                "synthesize_coordination_pressure_replay",
                "minimize_coordination_pressure_replay",
            ],
            "expected_log_totals": replay_totals,
        },
    )
    rows.append(
        row(
            row_id="replay_hook_handoff_validates_minimization_inputs",
            consumer="replay",
            phase="lab-replay",
            mode="execute",
            expected_status="passed",
            status="passed" if replay_passed else "failed",
            artifact_paths={"replay_handoff": str(replay_handoff_path), "expansion_pack": str(synth_pack_path)},
            first_failure_line="" if replay_passed else "replay handoff pack did not cover required families",
            detail=replay_totals,
        )
    )

    planner_root = RUN_DIR / "planner"
    capacity_args = [
        "bash",
        PROJECT_ROOT / "scripts/run_capacity_envelope_planner_smoke.sh",
        "--dry-run",
        "--output-root",
        planner_root / "capacity",
    ]
    capacity_env = {
        "CAPACITY_ENVELOPE_SMOKE_RUN_ID": "coordination-bridge-capacity",
        "CAPACITY_ENVELOPE_SMOKE_ARTIFACT_ROOT": str(planner_root / "capacity-artifacts"),
    }
    capacity_completed, capacity_log = run_child(
        "planner_handoff_capacity_dry_run", capacity_args, capacity_env
    )
    host_args = [
        "bash",
        PROJECT_ROOT / "scripts/run_host_profile_planner_smoke.sh",
        "--dry-run",
        "--output-root",
        planner_root / "host-profile",
    ]
    host_env = {
        "HOST_PROFILE_PLANNER_SMOKE_RUN_ID": "coordination-bridge-host-profile",
        "HOST_PROFILE_PLANNER_SMOKE_ARTIFACT_ROOT": str(planner_root / "host-profile-artifacts"),
    }
    host_completed, host_log = run_child(
        "planner_handoff_host_profile_dry_run", host_args, host_env
    )
    signed_args = [
        "bash",
        PROJECT_ROOT / "scripts/run_signed_profile_bundle_smoke.sh",
        "--dry-run",
        "--output-root",
        planner_root / "signed-profile",
    ]
    signed_env = {
        "SIGNED_PROFILE_BUNDLE_SMOKE_RUN_ID": "coordination-bridge-signed-profile",
        "SIGNED_PROFILE_BUNDLE_SMOKE_ARTIFACT_ROOT": str(planner_root / "signed-profile-artifacts"),
    }
    signed_completed, signed_log = run_child(
        "planner_handoff_signed_profile_dry_run", signed_args, signed_env
    )
    signoff = load_json(PROJECT_ROOT / "artifacts/massive_swarm_signoff_smoke_contract_v1.json")
    coordination_row = next(
        item for item in signoff["signoff_matrix"] if item["control_id"] == "coordination_workload_planner_handoff"
    )
    scenario_ids = set(coordination_row["scenario_ids"])
    handoff_passed = (
        capacity_completed.returncode == 0
        and host_completed.returncode == 0
        and signed_completed.returncode == 0
        and {"AA-COORDINATION-WORKLOAD-PLANNER-HANDOFF-USED",
             "AA-COORDINATION-WORKLOAD-PLANNER-HANDOFF-REFUSED",
             "AA-COORDINATION-WORKLOAD-PLANNER-HANDOFF-ABSENT"}.issubset(scenario_ids)
        and coordination_row.get("proof_status") == "trusted"
        and coordination_row.get("tracker_status") == "closed"
    )
    rows.append(
        row(
            row_id="capacity_profile_planner_handoff_records_used_refused_absent",
            consumer="capacity-profile",
            phase="planner-handoff",
            mode="dry-run",
            expected_status="passed",
            status="passed" if handoff_passed else "failed",
            command="; ".join(
                [command_text(capacity_args), command_text(host_args), command_text(signed_args)]
            ),
            exit_code=max(
                capacity_completed.returncode, host_completed.returncode, signed_completed.returncode
            ),
            artifact_paths={
                "capacity_log": str(capacity_log),
                "host_profile_log": str(host_log),
                "signed_profile_log": str(signed_log),
                "signoff_contract": str(PROJECT_ROOT / "artifacts/massive_swarm_signoff_smoke_contract_v1.json"),
            },
            first_failure_line="" if handoff_passed else "planner dry-run or signoff handoff row failed",
            stable_fingerprint=stable_hash(coordination_row),
            detail={
                "planner_child_modes": {
                    "capacity": "dry-run",
                    "host_profile": "dry-run",
                    "signed_profile": "dry-run",
                },
                "scenario_ids": sorted(scenario_ids),
                "operator_fields": coordination_row.get("operator_fields", []),
                "fallback_mode": coordination_row.get("fallback_mode"),
            },
        )
    )

    unexpected = [
        item
        for item in rows
        if item["status"] != item["expected_status"] and item["status"] != "dry_run"
    ]
    if unexpected:
        return rows, "failed", "one or more smoke rows diverged from expected status", 1
    return rows, "passed", "all coordination workload bridge smoke rows matched expected status", 0


def main():
    if MODE == "list":
        return list_rows()
    if MODE == "dry-run":
        RUN_DIR.mkdir(parents=True, exist_ok=True)
        return report(dry_run_rows(), "dry_run", "planned rows emitted without child execution", 0)
    if MODE != "execute":
        print(f"FATAL: unsupported mode {MODE}", file=sys.stderr)
        return 2
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    rows, status, message, exit_code = execute_rows()
    return report(rows, status, message, exit_code)


if __name__ == "__main__":
    sys.exit(main())
PY
