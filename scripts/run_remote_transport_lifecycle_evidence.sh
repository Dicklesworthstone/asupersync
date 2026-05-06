#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT_PATH="${REMOTE_TRANSPORT_LIFECYCLE_ARTIFACT:-${REPO_ROOT}/artifacts/wave2/remote_transport_lifecycle_evidence.json}"
OUTPUT_ROOT="${REMOTE_TRANSPORT_LIFECYCLE_OUTPUT_ROOT:-${REPO_ROOT}/target/remote-transport-lifecycle}"
RUN_ID="$(date -u +%Y%m%d_%H%M%S)"
CONTRACT_ONLY=0
TIMEOUT_SEC="${REMOTE_TRANSPORT_LIFECYCLE_TIMEOUT_SEC:-180}"
DRY_RUN=0
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"

usage() {
    cat <<'USAGE'
Usage: scripts/run_remote_transport_lifecycle_evidence.sh [options]

Options:
  --artifact <path>       Remote transport lifecycle evidence contract.
  --output-root <dir>     Directory for run_report.json and run.log.
  --run-id <id>           Deterministic run id for tests.
  --timeout-sec <sec>     Wall-clock timeout for the rch cargo proof.
  --contract-only         Validate the contract artifact without running cargo.
  --dry-run               Record the planned rch command without running cargo.
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

TEST_COMMAND=(
    env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 "RUSTFLAGS=-C debuginfo=0" "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wave2_remote_transport_lifecycle"
    cargo test -p asupersync --test remote_transport_lifecycle_contract --features test-internals -- --nocapture
)
RCH_COMMAND=("${RCH_BIN}" exec -- "${TEST_COMMAND[@]}")

: > "${RUN_LOG_PATH}"

if [[ "${CONTRACT_ONLY}" -eq 1 ]]; then
    TEST_STATUS=0
elif [[ "${DRY_RUN}" -eq 1 ]]; then
    {
        printf 'REMOTE_TRANSPORT_LIFECYCLE_COMMAND timeout_sec=%s command=' "$TIMEOUT_SEC"
        printf '%q ' "${RCH_COMMAND[@]}"
        printf '\n'
        printf 'REMOTE_TRANSPORT_LIFECYCLE_DRY_RUN command='
        printf '%q ' "${RCH_COMMAND[@]}"
        printf '\nREMOTE_TRANSPORT_LIFECYCLE_COMMAND_STATUS status=0 dry_run=true\n'
    } >> "${RUN_LOG_PATH}"
    TEST_STATUS=0
else
    if ! command -v "${RCH_BIN}" >/dev/null 2>&1; then
        echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
        exit 1
    fi
    {
        printf 'REMOTE_TRANSPORT_LIFECYCLE_COMMAND timeout_sec=%s command=' "$TIMEOUT_SEC"
        printf '%q ' "${RCH_COMMAND[@]}"
        printf '\n'
    } >> "${RUN_LOG_PATH}"
    set +e
    timeout "${TIMEOUT_SEC}" "${RCH_COMMAND[@]}" >> "${RUN_LOG_PATH}" 2>&1
    TEST_STATUS=$?
    set -e
    if grep -Eq '^\[RCH\] local \(|falling back to local' "${RUN_LOG_PATH}"; then
        TEST_STATUS=86
    fi
    echo "REMOTE_TRANSPORT_LIFECYCLE_COMMAND_STATUS status=${TEST_STATUS}" >> "${RUN_LOG_PATH}"
    cat "${RUN_LOG_PATH}"
fi

python3 - "$REPO_ROOT" "$ARTIFACT_PATH" "$RUN_LOG_PATH" "$RUN_REPORT_PATH" "$RUN_ID" "$TEST_STATUS" "$CONTRACT_ONLY" "$TIMEOUT_SEC" "$DRY_RUN" <<'PY'
import json
import re
import sys
from pathlib import Path

repo_root = Path(sys.argv[1]).resolve()
artifact_path = Path(sys.argv[2]).resolve()
run_log_path = Path(sys.argv[3]).resolve()
run_report_path = Path(sys.argv[4]).resolve()
run_id = sys.argv[5]
test_status = int(sys.argv[6])
contract_only = sys.argv[7] == "1"
timeout_sec = int(sys.argv[8])
dry_run = sys.argv[9] == "1"

contract = json.loads(artifact_path.read_text())
required_fields = contract["required_log_fields"]
expected_scenarios = [row["scenario_id"] for row in contract["scenario_matrix"]]
log_text = run_log_path.read_text() if run_log_path.exists() else ""
line_rows = []
first_failure = ""


def repo_relative(path):
    try:
        return str(path.resolve().relative_to(repo_root))
    except ValueError:
        return str(path)


def parse_log_line(line):
    if not line.startswith("REMOTE_TRANSPORT_LIFECYCLE "):
        return None
    row = {}
    for token in line.split()[1:]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        row[key] = value
    return row


for source_path in contract["source_evidence_paths"]:
    if not (repo_root / source_path).exists():
        first_failure = first_failure or f"missing_source:{source_path}"

for line in log_text.splitlines():
    row = parse_log_line(line)
    if row is None:
        continue
    missing = [field for field in required_fields if field not in row]
    if missing:
        row["first_failure"] = row.get("first_failure", "") or "missing_required_fields"
        first_failure = first_failure or f"{row.get('scenario_id', '<unknown>')}:missing:{','.join(missing)}"
    if row.get("verdict") != "pass":
        first_failure = first_failure or f"{row.get('scenario_id', '<unknown>')}:verdict:{row.get('verdict')}"
    line_rows.append(row)

observed_scenarios = {row.get("scenario_id", "") for row in line_rows}
missing_scenarios = [] if contract_only or dry_run else sorted(set(expected_scenarios) - observed_scenarios)
if not contract_only and not dry_run and missing_scenarios:
    first_failure = first_failure or "missing_scenarios:" + ",".join(missing_scenarios)
cargo_proof_passed = "test result: ok" in log_text and not missing_scenarios
timed_out_after_success = test_status == 124 and cargo_proof_passed
if test_status != 0 and not timed_out_after_success:
    first_failure = first_failure or f"cargo_test_status:{test_status}"

for command in contract["validation_commands"]:
    if ("cargo " in command or command.startswith("rustfmt ")) and "rch exec --" not in command:
        first_failure = first_failure or f"missing_rch:{command}"
    lowered = command.lower()
    for marker in ("password=", "token=", "secret=", "bearer "):
        if marker in lowered:
            first_failure = first_failure or f"sensitive_command_marker:{marker}"

validation_passed = first_failure == "" and (contract_only or dry_run or len(missing_scenarios) == 0)

report = {
    "schema_version": "remote-transport-lifecycle-run-report-v1",
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
    "observed_scenarios": sorted(observed_scenarios),
    "missing_scenarios": missing_scenarios,
    "log_rows": line_rows,
    "validation_commands": contract["validation_commands"],
    "test_status": test_status,
    "timeout_sec": timeout_sec,
    "timed_out_after_success": timed_out_after_success,
    "validation_passed": validation_passed,
    "first_failure": first_failure,
}
run_report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

if contract_only:
    for scenario_id in expected_scenarios:
        print(
            "REMOTE_TRANSPORT_LIFECYCLE_CONTRACT "
            f"bead_id={contract['bead_id']} scenario_id={scenario_id} "
            "verdict=contract_present first_failure="
        )

if not validation_passed:
    raise SystemExit(1)
PY
