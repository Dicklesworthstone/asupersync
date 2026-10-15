#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT_PATH="${GRPC_DEADLINE_HEALTH_ARTIFACT:-${REPO_ROOT}/artifacts/wave2/conformance_grpc_deadline_health_evidence.json}"
OUTPUT_ROOT="${GRPC_DEADLINE_HEALTH_OUTPUT_ROOT:-${REPO_ROOT}/target/grpc-deadline-health-conformance-evidence}"
RUN_ID="$(date -u +%Y%m%d_%H%M%S)"
CONTRACT_ONLY=0
TIMEOUT_SEC="${GRPC_DEADLINE_HEALTH_TIMEOUT_SEC:-180}"

usage() {
    cat <<'USAGE'
Usage: scripts/run_grpc_deadline_health_conformance_evidence.sh [options]

Options:
  --artifact <path>       gRPC deadline/health evidence contract.
  --output-root <dir>     Directory for run_report.json and run.log.
  --run-id <id>           Deterministic run id for tests.
  --timeout-sec <sec>     Wall-clock timeout for each rch cargo proof.
  --contract-only         Validate the contract artifact without running cargo.
  --dry-run               Print planned rch proof commands without running cargo.
  -h, --help              Show this help.
USAGE
}

DRY_RUN=0
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"

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
        --dry-run)
            DRY_RUN=1
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

DEADLINE_STATUS=0
HEALTH_STATUS=0

run_proof() {
    local label="$1"
    shift
    local -a rch_command=("${RCH_BIN}" exec -- "$@")

    {
        printf 'GRPC_DEADLINE_HEALTH_COMMAND label=%s timeout_sec=%s command=' "$label" "$TIMEOUT_SEC"
        printf '%q ' "${rch_command[@]}"
        printf '\n'
    } >> "${RUN_LOG_PATH}"

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf 'GRPC_DEADLINE_HEALTH_DRY_RUN label=%s command=' "$label" >> "${RUN_LOG_PATH}"
        printf '%q ' "${rch_command[@]}" >> "${RUN_LOG_PATH}"
        printf '\n' >> "${RUN_LOG_PATH}"
        echo "GRPC_DEADLINE_HEALTH_COMMAND_STATUS label=${label} status=0 dry_run=true" >> "${RUN_LOG_PATH}"
        return 0
    fi

    set +e
    timeout "${TIMEOUT_SEC}" "${rch_command[@]}" >> "${RUN_LOG_PATH}" 2>&1
    local status=$?
    set -e

    if grep -Eq '^\[RCH\] local \(|falling back to local' "${RUN_LOG_PATH}"; then
        status=86
    fi

    echo "GRPC_DEADLINE_HEALTH_COMMAND_STATUS label=${label} status=${status}" >> "${RUN_LOG_PATH}"
    return "${status}"
}

if [[ "${CONTRACT_ONLY}" -eq 0 && "${DRY_RUN}" -eq 0 && ! -x "${RCH_BIN}" ]]; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

if [[ "${CONTRACT_ONLY}" -eq 1 ]]; then
    : > "${RUN_LOG_PATH}"
else
    : > "${RUN_LOG_PATH}"
    run_proof grpc_deadline \
        env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 "RUSTFLAGS=-C debuginfo=0" "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wave2_grpc_deadline" \
        cargo test -p asupersync --test conformance --features test-internals grpc_deadline -- --nocapture || DEADLINE_STATUS=$?

    run_proof grpc_health \
        env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 "RUSTFLAGS=-C debuginfo=0" "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wave2_grpc_health" \
        cargo test -p asupersync --test conformance --features test-internals grpc_health -- --nocapture || HEALTH_STATUS=$?

    cat "${RUN_LOG_PATH}"
fi

python3 - "$REPO_ROOT" "$ARTIFACT_PATH" "$RUN_LOG_PATH" "$RUN_REPORT_PATH" "$RUN_ID" "$CONTRACT_ONLY" "$TIMEOUT_SEC" "$DEADLINE_STATUS" "$HEALTH_STATUS" <<'PY'
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
deadline_status = int(sys.argv[8])
health_status = int(sys.argv[9])
dry_run = any(
    "GRPC_DEADLINE_HEALTH_DRY_RUN " in line
    for line in Path(sys.argv[3]).read_text().splitlines()
) if Path(sys.argv[3]).exists() else False

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


def command_log_segment(label):
    start_marker = f"GRPC_DEADLINE_HEALTH_COMMAND label={label} "
    start = log_text.find(start_marker)
    if start < 0:
        return ""
    next_marker = log_text.find("GRPC_DEADLINE_HEALTH_COMMAND label=", start + len(start_marker))
    if next_marker < 0:
        return log_text[start:]
    return log_text[start:next_marker]


def effective_command_status(label, raw_status):
    segment = command_log_segment(label)
    if raw_status == 0:
        return 0, ""
    if (
        raw_status == 124
        and "Remote command finished: exit=0" in segment
        and "test result: ok" in segment
    ):
        return 0, "retrieval_timeout_after_remote_success"
    return raw_status, ""


effective_deadline_status, deadline_status_note = effective_command_status("grpc_deadline", deadline_status)
effective_health_status, health_status_note = effective_command_status("grpc_health", health_status)


def row_suite_status(suite_id):
    if suite_id == "grpc_deadline":
        return effective_deadline_status
    if suite_id == "grpc_health":
        return effective_health_status
    return 1


for source_path in contract["source_evidence_paths"]:
    if not (repo_root / source_path).exists():
        drifts.append(f"missing_source:{source_path}")

for field in required_fields:
    for scenario in contract["scenario_matrix"]:
        if field not in scenario and field not in {"bead_id", "verdict", "first_failure", "actual_status"}:
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
    missing_markers = [] if contract_only or dry_run else [marker for marker in markers if marker not in log_text]
    suite_status = row_suite_status(suite_id)
    first_failure = ""

    if contract_only or dry_run:
        verdict = "contract_present"
        actual_status = "dry_run" if dry_run else scenario.get("actual_status", "contract_only")
    elif suite_status != 0:
        verdict = "fail"
        first_failure = f"{suite_id}_status:{suite_status}"
        actual_status = "suite_failed"
    elif missing_markers:
        verdict = "fail"
        first_failure = "missing_markers:" + ",".join(missing_markers)
        actual_status = "missing:" + ",".join(missing_markers)
    elif test_result_ok_count < 2:
        verdict = "fail"
        first_failure = "missing_cargo_ok_summary"
        actual_status = "missing_cargo_ok_summary"
    else:
        verdict = "pass"
        actual_status = "observed:" + ",".join(markers)
        observed_scenarios.append(scenario_id)

    row = {
        "bead_id": contract["bead_id"],
        "suite_id": suite_id,
        "scenario_id": scenario_id,
        "grpc_method": scenario["grpc_method"],
        "metadata_in": scenario["metadata_in"],
        "metadata_out": scenario["metadata_out"],
        "virtual_now": scenario["virtual_now"],
        "deadline": scenario["deadline"],
        "expected_status": scenario["expected_status"],
        "actual_status": actual_status,
        "health_state": scenario["health_state"],
        "cancellation_observed": scenario["cancellation_observed"],
        "verdict": verdict,
        "first_failure": first_failure,
    }
    rows.append(row)
    emit("GRPC_DEADLINE_HEALTH_CONFORMANCE" if not contract_only else "GRPC_DEADLINE_HEALTH_CONTRACT", row)
    if verdict == "fail":
        drifts.append(f"{scenario_id}:{first_failure}")

validation_passed = not drifts and (contract_only or dry_run or len(observed_scenarios) == len(expected_scenarios))
report = {
    "schema_version": "grpc-deadline-health-conformance-run-report-v1",
    "contract_schema_version": contract["schema_version"],
    "bead_id": contract["bead_id"],
    "capability_id": contract["capability_id"],
    "run_id": run_id,
    "contract_only": contract_only,
    "dry_run": dry_run,
    "artifact_path": repo_relative(artifact_path),
    "run_report_path": repo_relative(run_report_path),
    "run_log_path": repo_relative(run_log_path),
    "required_log_fields": required_fields,
    "expected_scenarios": expected_scenarios,
    "observed_scenarios": observed_scenarios,
    "missing_scenarios": sorted(set(expected_scenarios) - set(observed_scenarios)) if not contract_only else [],
    "validation_commands": contract["validation_commands"],
    "deadline_status": effective_deadline_status,
    "health_status": effective_health_status,
    "raw_deadline_status": deadline_status,
    "raw_health_status": health_status,
    "deadline_status_note": deadline_status_note,
    "health_status_note": health_status_note,
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
