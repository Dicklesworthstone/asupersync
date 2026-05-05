#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT_PATH="${ACTOR_TRACE_CONFORMANCE_ARTIFACT:-${REPO_ROOT}/artifacts/wave2/conformance_actor_mailbox_trace_event_evidence.json}"
OUTPUT_ROOT="${ACTOR_TRACE_CONFORMANCE_OUTPUT_ROOT:-${REPO_ROOT}/target/actor-trace-conformance-evidence}"
RUN_ID="$(date -u +%Y%m%d_%H%M%S)"
CONTRACT_ONLY=0
TIMEOUT_SEC="${ACTOR_TRACE_CONFORMANCE_TIMEOUT_SEC:-240}"

usage() {
    cat <<'USAGE'
Usage: scripts/run_actor_trace_conformance_evidence.sh [options]

Options:
  --artifact <path>       Actor/trace conformance evidence contract.
  --output-root <dir>     Directory for run_report.json and run.log.
  --run-id <id>           Deterministic run id for tests.
  --timeout-sec <sec>     Wall-clock timeout for each rch cargo proof.
  --contract-only         Validate the contract artifact without running cargo.
  -h, --help              Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --artifact)
            ARTIFACT_PATH="${2:-}"
            shift 2
            ;;
        --output-root)
            OUTPUT_ROOT="${2:-}"
            shift 2
            ;;
        --run-id)
            RUN_ID="${2:-}"
            shift 2
            ;;
        --timeout-sec)
            TIMEOUT_SEC="${2:-}"
            shift 2
            ;;
        --contract-only)
            CONTRACT_ONLY=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

REPORT_DIR="${OUTPUT_ROOT}/run_${RUN_ID}"
RUN_LOG_PATH="${REPORT_DIR}/run.log"
RUN_REPORT_PATH="${REPORT_DIR}/run_report.json"
mkdir -p "${REPORT_DIR}"

ACTOR_STATUS=0
TRACE_STATUS=0

run_proof() {
    local label="$1"
    shift

    {
        printf 'ACTOR_TRACE_CONFORMANCE_COMMAND label=%s timeout_sec=%s command=' "$label" "$TIMEOUT_SEC"
        printf '%q ' "$@"
        printf '\n'
    } >> "${RUN_LOG_PATH}"

    set +e
    timeout "${TIMEOUT_SEC}" "$@" >> "${RUN_LOG_PATH}" 2>&1
    local status=$?
    set -e

    echo "ACTOR_TRACE_CONFORMANCE_COMMAND_STATUS label=${label} status=${status}" >> "${RUN_LOG_PATH}"
    return "${status}"
}

if [[ "${CONTRACT_ONLY}" -eq 1 ]]; then
    : > "${RUN_LOG_PATH}"
else
    : > "${RUN_LOG_PATH}"
    run_proof actor_mailbox \
        rch exec -- \
        env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 "RUSTFLAGS=-C debuginfo=0" "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wave2_actor_mailbox" \
        cargo test -p asupersync --test conformance --features test-internals actor_mailbox_protocol -- --nocapture || ACTOR_STATUS=$?

    run_proof trace_event \
        rch exec -- \
        env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 "RUSTFLAGS=-C debuginfo=0" "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wave2_trace_event" \
        cargo test -p asupersync --test conformance --features test-internals trace_event -- --nocapture || TRACE_STATUS=$?

    cat "${RUN_LOG_PATH}"
fi

python3 - "$REPO_ROOT" "$ARTIFACT_PATH" "$RUN_LOG_PATH" "$RUN_REPORT_PATH" "$RUN_ID" "$CONTRACT_ONLY" "$TIMEOUT_SEC" "$ACTOR_STATUS" "$TRACE_STATUS" <<'PY'
import json
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
artifact_path = Path(sys.argv[2]).resolve()
run_log_path = Path(sys.argv[3]).resolve()
run_report_path = Path(sys.argv[4]).resolve()
run_id = sys.argv[5]
contract_only = sys.argv[6] == "1"
timeout_sec = int(sys.argv[7])
actor_status = int(sys.argv[8])
trace_status = int(sys.argv[9])

contract = json.loads(artifact_path.read_text())
required_fields = contract["required_log_fields"]
expected_scenarios = [row["scenario_id"] for row in contract["scenario_matrix"]]
log_text = run_log_path.read_text() if run_log_path.exists() else ""
rows = []
drifts = []


def repo_relative(path):
    try:
        return str(path.resolve().relative_to(repo_root))
    except ValueError:
        return str(path)


def compact(value):
    if isinstance(value, list):
        return ",".join(str(item).replace(" ", "_") for item in value)
    return str(value).replace(" ", "_")


def emit(prefix, row):
    ordered = []
    for key in required_fields:
        ordered.append(f"{key}={compact(row.get(key, ''))}")
    print(prefix + " " + " ".join(ordered))


def row_suite_status(suite_id):
    if suite_id == "actor_mailbox_protocol":
        return actor_status
    if suite_id == "trace_event_schema":
        return trace_status
    return 1


for source_path in contract["source_evidence_paths"]:
    if not (repo_root / source_path).exists():
        drifts.append(f"missing_source:{source_path}")

for field in required_fields:
    for scenario in contract["scenario_matrix"]:
        if field not in scenario and field not in {"bead_id", "verdict", "first_failure", "actual_sequence"}:
            drifts.append(f"{scenario['scenario_id']}:missing_required_field:{field}")

for command in contract["validation_commands"]:
    if "cargo " in command and "rch exec --" not in command:
        drifts.append(f"missing_rch:{command}")
    lowered = command.lower()
    for marker in ("password=", "token=", "secret=", "bearer "):
        if marker in lowered:
            drifts.append(f"sensitive_command_marker:{marker}")

test_result_ok_count = len(re.findall(r"test result: ok", log_text))
observed_scenarios = []

for scenario in contract["scenario_matrix"]:
    suite_id = scenario["suite_id"]
    scenario_id = scenario["scenario_id"]
    markers = scenario.get("test_markers", [])
    missing_markers = [] if contract_only else [marker for marker in markers if marker not in log_text]
    suite_status = row_suite_status(suite_id)
    first_failure = ""

    if contract_only:
        verdict = "contract_present"
        actual_sequence = "contract_only"
    elif suite_status != 0:
        verdict = "fail"
        first_failure = f"{suite_id}_status:{suite_status}"
        actual_sequence = "suite_failed"
    elif missing_markers:
        verdict = "fail"
        first_failure = "missing_markers:" + ",".join(missing_markers)
        actual_sequence = "missing:" + ",".join(missing_markers)
    elif test_result_ok_count < 2:
        verdict = "fail"
        first_failure = "missing_cargo_ok_summary"
        actual_sequence = "missing_cargo_ok_summary"
    else:
        verdict = "pass"
        actual_sequence = "observed:" + ",".join(markers)
        observed_scenarios.append(scenario_id)

    row = {
        "bead_id": contract["bead_id"],
        "suite_id": suite_id,
        "scenario_id": scenario_id,
        "actor_id": scenario["actor_id"],
        "mailbox_capacity": scenario["mailbox_capacity"],
        "messages_sent": scenario["messages_sent"],
        "messages_received": scenario["messages_received"],
        "cancellation_point": scenario["cancellation_point"],
        "trace_event_count": scenario["trace_event_count"],
        "replay_seed": scenario["replay_seed"],
        "replay_verdict": scenario["replay_verdict"],
        "obligation_delta": scenario["obligation_delta"],
        "expected_sequence": scenario["expected_sequence"],
        "actual_sequence": actual_sequence,
        "verdict": verdict,
        "first_failure": first_failure,
    }
    rows.append(row)
    emit("ACTOR_TRACE_CONFORMANCE" if not contract_only else "ACTOR_TRACE_CONFORMANCE_CONTRACT", row)
    if verdict == "fail":
        drifts.append(f"{scenario_id}:{first_failure}")

validation_passed = not drifts and (contract_only or len(observed_scenarios) == len(expected_scenarios))
report = {
    "schema_version": "conformance-actor-mailbox-trace-event-run-report-v1",
    "contract_schema_version": contract["schema_version"],
    "bead_id": contract["bead_id"],
    "capability_id": contract["capability_id"],
    "run_id": run_id,
    "contract_only": contract_only,
    "artifact_path": repo_relative(artifact_path),
    "run_report_path": repo_relative(run_report_path),
    "run_log_path": repo_relative(run_log_path),
    "required_log_fields": required_fields,
    "expected_scenarios": expected_scenarios,
    "observed_scenarios": observed_scenarios,
    "missing_scenarios": sorted(set(expected_scenarios) - set(observed_scenarios)) if not contract_only else [],
    "validation_commands": contract["validation_commands"],
    "actor_status": actor_status,
    "trace_status": trace_status,
    "timeout_sec": timeout_sec,
    "cargo_ok_summary_count": test_result_ok_count,
    "validation_passed": validation_passed,
    "first_failure": drifts[0] if drifts else "",
    "drifts": drifts,
    "log_rows": rows,
}
run_report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

if not validation_passed:
    raise SystemExit(1)
PY
