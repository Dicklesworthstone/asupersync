#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT_PATH="${WASM_SW_DIRECT_RUNTIME_ARTIFACT:-${REPO_ROOT}/artifacts/wave2/wasm_service_worker_direct_runtime_evidence.json}"
OUTPUT_ROOT="${WASM_SW_DIRECT_RUNTIME_OUTPUT_ROOT:-${REPO_ROOT}/target/wasm-service-worker-direct-runtime-evidence}"
RUN_ID="$(date -u +%Y%m%d_%H%M%S)"
CONTRACT_ONLY=0
TIMEOUT_SEC="${WASM_SW_DIRECT_RUNTIME_TIMEOUT_SEC:-180}"

usage() {
    cat <<'USAGE'
Usage: scripts/run_wasm_service_worker_direct_runtime_evidence.sh [options]

Options:
  --artifact <path>       Service-worker direct-runtime evidence contract.
  --output-root <dir>     Directory for run_report.json and run.log.
  --run-id <id>           Deterministic run id for tests.
  --timeout-sec <sec>     Wall-clock timeout for each proof command.
  --contract-only         Validate the contract artifact without running proofs.
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

RUST_STATUS=0
BROWSER_STATUS=0

run_proof() {
    local label="$1"
    shift

    {
        printf 'WASM_SERVICE_WORKER_DIRECT_RUNTIME_COMMAND label=%s timeout_sec=%s command=' "$label" "$TIMEOUT_SEC"
        printf '%q ' "$@"
        printf '\n'
    } >> "${RUN_LOG_PATH}"

    set +e
    timeout "${TIMEOUT_SEC}" "$@" >> "${RUN_LOG_PATH}" 2>&1
    local status=$?
    set -e

    echo "WASM_SERVICE_WORKER_DIRECT_RUNTIME_COMMAND_STATUS label=${label} status=${status}" >> "${RUN_LOG_PATH}"
    return "${status}"
}

if [[ "${CONTRACT_ONLY}" -eq 1 ]]; then
    : > "${RUN_LOG_PATH}"
else
    : > "${RUN_LOG_PATH}"
    run_proof rust_contract \
        rch exec -- \
        env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 "RUSTFLAGS=-C debuginfo=0" "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wave2_wasm_sw_broker_contract" \
        cargo test -p asupersync --test wasm_service_worker_broker_contract --features test-internals,wasm-browser-dev -- --nocapture || RUST_STATUS=$?

    run_proof browser_fixture \
        bash "${REPO_ROOT}/scripts/validate_service_worker_broker_consumer.sh" || BROWSER_STATUS=$?

    cat "${RUN_LOG_PATH}"
fi

python3 - "$REPO_ROOT" "$ARTIFACT_PATH" "$RUN_LOG_PATH" "$RUN_REPORT_PATH" "$RUN_ID" "$CONTRACT_ONLY" "$TIMEOUT_SEC" "$RUST_STATUS" "$BROWSER_STATUS" <<'PY'
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
rust_status = int(sys.argv[8])
browser_status = int(sys.argv[9])

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
    start_marker = f"WASM_SERVICE_WORKER_DIRECT_RUNTIME_COMMAND label={label} "
    start = log_text.find(start_marker)
    if start < 0:
        return ""
    next_marker = log_text.find(
        "WASM_SERVICE_WORKER_DIRECT_RUNTIME_COMMAND label=",
        start + len(start_marker),
    )
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


effective_rust_status, rust_status_note = effective_command_status("rust_contract", rust_status)
effective_browser_status = browser_status
browser_status_note = ""

browser_result_root = repo_root / "target/e2e-results/service_worker_broker_consumer"
browser_summary = None
browser_summary_path = None
if not contract_only and browser_result_root.exists():
    summaries = sorted(
        browser_result_root.glob("*/summary.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if summaries:
        browser_summary_path = summaries[0]
        browser_summary = json.loads(browser_summary_path.read_text())

browser_summary_text = json.dumps(browser_summary or {}, sort_keys=True)
combined_browser_text = log_text + "\n" + browser_summary_text
browser_checks = (browser_summary or {}).get("checks", {})


def check_browser_expectations(scenario_id):
    if contract_only:
        return []
    failures = []
    if effective_browser_status != 0:
        failures.append(f"browser_fixture_status:{effective_browser_status}")
    if browser_summary is None:
        failures.append("missing_browser_summary")
        return failures
    expectations = {
        "service_worker_install_activate_registers_broker": [
            ("real_browser_run_ok", True),
            ("browser_final_phase_is_cleanup_complete", True),
            ("browser_controller_ready", True),
            ("browser_broker_supported", True),
            ("browser_broker_reason", "supported"),
            ("browser_broker_runtime_context", "service_worker"),
            ("browser_direct_execution_reason", "service_worker_direct_runtime_not_shipped"),
            ("browser_registration_requested_lane", "lane.browser.service_worker.broker"),
            ("browser_registration_fallback_lane_id", "lane.browser.dedicated_worker.direct_runtime"),
            ("browser_registration_lifecycle_state", "quiescent"),
        ],
        "service_worker_fetch_message_persists_restartable_work": [
            ("browser_pending_work_count", 1),
            ("work_marker", True),
        ],
        "service_worker_handoff_targets_dedicated_worker": [
            ("browser_handoff_count", 1),
            ("browser_handoff_target_lane_id", "lane.browser.dedicated_worker.direct_runtime"),
            ("browser_handoff_reason", "service_worker_direct_runtime_not_shipped"),
            ("handoff_marker", True),
        ],
        "service_worker_restart_reopens_durable_state": [
            ("browser_reopened_pending_work_count", 1),
            ("browser_reopened_handoff_count", 1),
            ("reopen_marker", True),
        ],
        "service_worker_protocol_mismatch_fails_closed": [
            ("browser_mismatch_supported", False),
            ("browser_mismatch_reason", "broker_protocol_version_mismatch"),
            ("mismatch_marker", True),
        ],
        "service_worker_cleanup_returns_to_quiescence": [
            ("browser_cleared_count", lambda value: isinstance(value, int) and value >= 3),
            ("browser_post_cleanup_registration_missing", True),
            ("browser_post_cleanup_pending_work_count", 0),
            ("browser_post_cleanup_handoff_count", 0),
            ("cleanup_marker", True),
        ],
    }
    for key, expected in expectations.get(scenario_id, []):
        actual = browser_checks.get(key)
        if callable(expected):
            if not expected(actual):
                failures.append(f"{key}:unexpected:{actual!r}")
        elif actual != expected:
            failures.append(f"{key}:expected:{expected!r}:actual:{actual!r}")
    return failures


for source_path in contract["source_evidence_paths"]:
    if not (repo_root / source_path).exists():
        drifts.append(f"missing_source:{source_path}")

for field in required_fields:
    for scenario in contract["scenario_matrix"]:
        if field not in scenario and field not in {"bead_id", "verdict", "first_failure"}:
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
    scenario_id = scenario["scenario_id"]
    proof_source = scenario.get("proof_source", "")
    markers = scenario.get("test_markers", [])
    marker_text = combined_browser_text if proof_source == "browser_fixture" else log_text
    missing_markers = [] if contract_only else [marker for marker in markers if marker not in marker_text]
    browser_failures = [] if proof_source != "browser_fixture" else check_browser_expectations(scenario_id)
    first_failure = ""

    if contract_only:
        verdict = "contract_present"
        actual_reason = scenario["actual_reason"]
    elif proof_source == "rust_contract" and effective_rust_status != 0:
        verdict = "fail"
        first_failure = f"rust_contract_status:{effective_rust_status}"
        actual_reason = "rust_contract_failed"
    elif proof_source == "rust_contract" and test_result_ok_count < 1:
        verdict = "fail"
        first_failure = "missing_cargo_ok_summary"
        actual_reason = "missing_cargo_ok_summary"
    elif proof_source == "browser_fixture" and browser_failures:
        verdict = "fail"
        first_failure = "browser_expectation:" + ",".join(browser_failures)
        actual_reason = "browser_expectation_failed"
    elif missing_markers:
        verdict = "fail"
        first_failure = "missing_markers:" + ",".join(missing_markers)
        actual_reason = "missing:" + ",".join(missing_markers)
    else:
        verdict = "pass"
        actual_reason = scenario["actual_reason"]
        observed_scenarios.append(scenario_id)

    row = {
        "bead_id": contract["bead_id"],
        "scenario_id": scenario_id,
        "host_context": scenario["host_context"],
        "service_worker_scope": scenario["service_worker_scope"],
        "lifecycle_event": scenario["lifecycle_event"],
        "selected_lane": scenario["selected_lane"],
        "direct_runtime_supported": scenario["direct_runtime_supported"],
        "fallback_target": scenario["fallback_target"],
        "region_count_before": scenario["region_count_before"],
        "region_count_after": scenario["region_count_after"],
        "cancel_event_count": scenario["cancel_event_count"],
        "durable_state_key": scenario["durable_state_key"],
        "expected_reason": scenario["expected_reason"],
        "actual_reason": actual_reason,
        "verdict": verdict,
        "first_failure": first_failure,
    }
    rows.append(row)
    emit(
        "WASM_SERVICE_WORKER_DIRECT_RUNTIME"
        if not contract_only
        else "WASM_SERVICE_WORKER_DIRECT_RUNTIME_CONTRACT",
        row,
    )
    if verdict == "fail":
        drifts.append(f"{scenario_id}:{first_failure}")

validation_passed = not drifts and (
    contract_only or len(observed_scenarios) == len(expected_scenarios)
)
report = {
    "schema_version": "wasm-service-worker-direct-runtime-run-report-v1",
    "contract_schema_version": contract["schema_version"],
    "bead_id": contract["bead_id"],
    "capability_id": contract["capability_id"],
    "blocker_bead_id": contract["decision"]["blocker_bead_id"],
    "support_class_after": contract["decision"]["support_class_after"],
    "run_id": run_id,
    "contract_only": contract_only,
    "artifact_path": repo_relative(artifact_path),
    "run_report_path": repo_relative(run_report_path),
    "run_log_path": repo_relative(run_log_path),
    "browser_summary_path": repo_relative(browser_summary_path) if browser_summary_path else "",
    "required_log_fields": required_fields,
    "expected_scenarios": expected_scenarios,
    "observed_scenarios": observed_scenarios,
    "missing_scenarios": sorted(set(expected_scenarios) - set(observed_scenarios)) if not contract_only else [],
    "validation_commands": contract["validation_commands"],
    "rust_status": effective_rust_status,
    "browser_status": effective_browser_status,
    "raw_rust_status": rust_status,
    "raw_browser_status": browser_status,
    "rust_status_note": rust_status_note,
    "browser_status_note": browser_status_note,
    "timeout_sec": timeout_sec,
    "cargo_ok_summary_count": test_result_ok_count,
    "validation_passed": validation_passed,
    "first_failure": drifts[0] if drifts else "",
    "drifts": drifts,
    "browser_checks": browser_checks,
    "log_rows": rows,
}
run_report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

if not validation_passed:
    raise SystemExit(1)
PY
