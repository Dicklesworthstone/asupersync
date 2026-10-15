#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT_PATH="${WASM_SHARED_DIRECT_RUNTIME_ARTIFACT:-${REPO_ROOT}/artifacts/wave2/wasm_shared_worker_direct_runtime_evidence.json}"
OUTPUT_ROOT="${WASM_SHARED_DIRECT_RUNTIME_OUTPUT_ROOT:-${REPO_ROOT}/target/wasm-shared-worker-direct-runtime-evidence}"
RUN_ID="$(date -u +%Y%m%d_%H%M%S)"
CONTRACT_ONLY=0
TIMEOUT_SEC="${WASM_SHARED_DIRECT_RUNTIME_TIMEOUT_SEC:-180}"

usage() {
    cat <<'USAGE'
Usage: scripts/run_wasm_shared_worker_direct_runtime_evidence.sh [options]

Options:
  --artifact <path>       Shared-worker direct-runtime evidence contract.
  --output-root <dir>     Directory for run_report.json and run.log.
  --run-id <id>           Deterministic run id for tests.
  --timeout-sec <sec>     Wall-clock timeout for each proof command.
  --contract-only         Validate the contract artifact without running proofs.
  --dry-run               Print planned proof commands without running cargo or browser fixtures.
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

RUST_STATUS=0
BROWSER_STATUS=0

run_proof() {
    local label="$1"
    shift
    local -a command=("$@")
    if [[ "$label" == "rust_contract" ]]; then
        command=("${RCH_BIN}" exec -- "$@")
    fi

    {
        printf 'WASM_SHARED_WORKER_DIRECT_RUNTIME_COMMAND label=%s timeout_sec=%s command=' "$label" "$TIMEOUT_SEC"
        printf '%q ' "${command[@]}"
        printf '\n'
    } >> "${RUN_LOG_PATH}"

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf 'WASM_SHARED_WORKER_DIRECT_RUNTIME_DRY_RUN label=%s command=' "$label" >> "${RUN_LOG_PATH}"
        printf '%q ' "${command[@]}" >> "${RUN_LOG_PATH}"
        printf '\n' >> "${RUN_LOG_PATH}"
        echo "WASM_SHARED_WORKER_DIRECT_RUNTIME_COMMAND_STATUS label=${label} status=0 dry_run=true" >> "${RUN_LOG_PATH}"
        return 0
    fi

    set +e
    timeout "${TIMEOUT_SEC}" "${command[@]}" >> "${RUN_LOG_PATH}" 2>&1
    local status=$?
    set -e

    if [[ "$label" == "rust_contract" ]] && grep -Eq '^\[RCH\] local \(|falling back to local' "${RUN_LOG_PATH}"; then
        status=86
    fi

    echo "WASM_SHARED_WORKER_DIRECT_RUNTIME_COMMAND_STATUS label=${label} status=${status}" >> "${RUN_LOG_PATH}"
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
    run_proof rust_contract \
        env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 "RUSTFLAGS=-C debuginfo=0" "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wave2_wasm_shared_contract" \
        cargo test -p asupersync --test wasm_shared_worker_tenancy_lifecycle_contract --features test-internals,wasm-browser-dev -- --nocapture || RUST_STATUS=$?

    run_proof browser_fixture \
        bash "${REPO_ROOT}/scripts/validate_shared_worker_consumer.sh" || BROWSER_STATUS=$?

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
dry_run = any(
    "WASM_SHARED_WORKER_DIRECT_RUNTIME_DRY_RUN " in line
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
    start_marker = f"WASM_SHARED_WORKER_DIRECT_RUNTIME_COMMAND label={label} "
    start = log_text.find(start_marker)
    if start < 0:
        return ""
    next_marker = log_text.find(
        "WASM_SHARED_WORKER_DIRECT_RUNTIME_COMMAND label=",
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


def list_contains_all(value, expected):
    return isinstance(value, list) and all(item in value for item in expected)


effective_rust_status, rust_status_note = effective_command_status("rust_contract", rust_status)
effective_browser_status = browser_status
browser_status_note = ""

browser_result_root = repo_root / "target/e2e-results/shared_worker_consumer"
browser_summary = None
browser_summary_path = None
if not contract_only and not dry_run and browser_result_root.exists():
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
    if contract_only or dry_run:
        return []
    failures = []
    if effective_browser_status != 0:
        failures.append(f"browser_fixture_status:{effective_browser_status}")
    if browser_summary is None:
        failures.append("missing_browser_summary")
        return failures
    expectations = {
        "shared_worker_attach_baseline": [
            ("real_browser_run_ok", True),
            ("browser_scenario_id", "SHARED-WORKER-CONSUMER"),
            ("reuse_page_one_mode", "shared_worker"),
            ("reuse_page_one_direct_execution_reason_code", "shared_worker_direct_runtime_not_shipped"),
            ("close_lifecycle_states", lambda value: list_contains_all(value, ["terminated"])),
        ],
        "shared_worker_multi_page_reuse": [
            ("reuse_page_one_mode", "shared_worker"),
            ("reuse_page_two_mode", "shared_worker"),
            ("reuse_page_one_client_count", 2),
            ("reuse_page_two_client_count", 2),
            ("reuse_attach_count", lambda value: isinstance(value, int) and value >= 2),
            ("reuse_client_ids", lambda value: list_contains_all(value, ["page-one", "page-two"])),
            ("reuse_worker_name", "shared-worker-reuse-cluster"),
        ],
        "shared_worker_protocol_mismatch_fallback": [
            ("mismatch_mode", "fallback"),
            ("mismatch_reason", "coordinator_protocol_version_mismatch"),
            ("mismatch_fallback_lane_id", "lane.browser.main_thread.direct_runtime"),
            ("mismatch_direct_execution_reason_code", "shared_worker_direct_runtime_not_shipped"),
        ],
        "shared_worker_attach_crash_fallback": [
            ("crash_mode", "fallback"),
            ("crash_reason", "coordinator_bootstrap_failure"),
            ("crash_fallback_lane_id", "lane.browser.main_thread.direct_runtime"),
            ("crash_direct_execution_reason_code", "shared_worker_direct_runtime_not_shipped"),
        ],
        "shared_worker_client_detach_cleanup": [
            ("close_lifecycle_states", lambda value: isinstance(value, list) and value == ["terminated", "terminated"]),
        ],
        "shared_worker_client_churn_rejoin": [
            ("churn_mode", "shared_worker"),
            ("churn_client_ids", ["page-three"]),
            ("churn_attach_count", lambda value: isinstance(value, int) and value >= 1),
            ("churn_direct_execution_reason_code", "shared_worker_direct_runtime_not_shipped"),
            ("churn_close_lifecycle_state", "terminated"),
        ],
        "shared_worker_crash_recovery_reconnect": [
            ("recovery_mode", "shared_worker"),
            ("recovery_client_ids", ["crash-recovery"]),
            ("recovery_attach_count", lambda value: isinstance(value, int) and value >= 1),
            ("recovery_direct_execution_reason_code", "shared_worker_direct_runtime_not_shipped"),
            ("recovery_close_lifecycle_state", "terminated"),
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
    missing_markers = [] if contract_only or dry_run else [marker for marker in markers if marker not in marker_text]
    browser_failures = [] if dry_run or proof_source != "browser_fixture" else check_browser_expectations(scenario_id)
    first_failure = ""

    if contract_only or dry_run:
        verdict = "contract_present"
        actual_reason = "dry_run" if dry_run else scenario["actual_reason"]
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
        "client_instance_id": scenario["client_instance_id"],
        "client_kind": scenario["client_kind"],
        "selected_lane": scenario["selected_lane"],
        "handshake_state": scenario["handshake_state"],
        "region_count_before": scenario["region_count_before"],
        "region_count_after": scenario["region_count_after"],
        "detach_event": scenario["detach_event"],
        "cancellation_observed": scenario["cancellation_observed"],
        "fallback_selected": scenario["fallback_selected"],
        "expected_reason": scenario["expected_reason"],
        "actual_reason": actual_reason,
        "verdict": verdict,
        "first_failure": first_failure,
    }
    rows.append(row)
    emit(
        "WASM_SHARED_WORKER_DIRECT_RUNTIME"
        if not contract_only
        else "WASM_SHARED_WORKER_DIRECT_RUNTIME_CONTRACT",
        row,
    )
    if verdict == "fail":
        drifts.append(f"{scenario_id}:{first_failure}")

validation_passed = not drifts and (
    contract_only or dry_run or len(observed_scenarios) == len(expected_scenarios)
)
report = {
    "schema_version": "wasm-shared-worker-direct-runtime-run-report-v1",
    "contract_schema_version": contract["schema_version"],
    "bead_id": contract["bead_id"],
    "capability_id": contract["capability_id"],
    "blocker_bead_id": contract["decision"]["blocker_bead_id"],
    "support_class_after": contract["decision"]["support_class_after"],
    "run_id": run_id,
    "contract_only": contract_only,
    "dry_run": dry_run,
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
