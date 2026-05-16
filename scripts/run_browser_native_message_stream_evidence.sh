#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT_PATH="${BROWSER_NATIVE_MESSAGE_STREAM_ARTIFACT:-${REPO_ROOT}/artifacts/wave2/browser_native_message_and_stream_apis_evidence.json}"
OUTPUT_ROOT="${BROWSER_NATIVE_MESSAGE_STREAM_OUTPUT_ROOT:-${REPO_ROOT}/target/browser-native-message-stream-evidence}"
RUN_ID="$(date -u +%Y%m%d_%H%M%S)"
CONTRACT_ONLY=0
TIMEOUT_SEC="${BROWSER_NATIVE_MESSAGE_STREAM_TIMEOUT_SEC:-180}"
DRY_RUN=0
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"
RCH_LOCAL_FALLBACK_PATTERN='^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally'

usage() {
    cat <<'USAGE'
Usage: scripts/run_browser_native_message_stream_evidence.sh [options]

Options:
  --artifact <path>       Browser-native message/stream evidence contract.
  --output-root <dir>     Directory for run_report.json and run.log.
  --run-id <id>           Deterministic run id for tests.
  --timeout-sec <sec>     Wall-clock timeout for each proof command.
  --contract-only         Validate the contract artifact without running proofs.
  --dry-run               Print planned proof commands without running cargo or browser fixtures.
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
BROWSER_RUN_PATH="${REPORT_DIR}/browser-run.json"
mkdir -p "${REPORT_DIR}"

RUST_STATUS=0
BROWSER_STATUS=0

require_cmd() {
    local cmd="$1"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "FATAL: required command not found: ${cmd}" >&2
        exit 1
    fi
}

run_proof() {
    local label="$1"
    shift
    local -a rch_command=("${RCH_BIN}" exec -- "$@")

    {
        printf 'BROWSER_NATIVE_MESSAGE_STREAM_COMMAND label=%s timeout_sec=%s command=' "$label" "$TIMEOUT_SEC"
        printf '%q ' "${rch_command[@]}"
        printf '\n'
    } >> "${RUN_LOG_PATH}"

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf 'BROWSER_NATIVE_MESSAGE_STREAM_DRY_RUN label=%s command=' "$label" >> "${RUN_LOG_PATH}"
        printf '%q ' "${rch_command[@]}" >> "${RUN_LOG_PATH}"
        printf '\n' >> "${RUN_LOG_PATH}"
        echo "BROWSER_NATIVE_MESSAGE_STREAM_COMMAND_STATUS label=${label} status=0 dry_run=true" >> "${RUN_LOG_PATH}"
        return 0
    fi

    set +e
    timeout "${TIMEOUT_SEC}" "${rch_command[@]}" >> "${RUN_LOG_PATH}" 2>&1
    local status=$?
    set -e

    if grep -Eiq "${RCH_LOCAL_FALLBACK_PATTERN}" "${RUN_LOG_PATH}"; then
        status=86
    fi

    echo "BROWSER_NATIVE_MESSAGE_STREAM_COMMAND_STATUS label=${label} status=${status}" >> "${RUN_LOG_PATH}"
    return "${status}"
}

run_browser_fixture() {
    require_cmd node
    require_cmd npm
    require_cmd npx
    require_cmd python3

    local fixture_dir="${REPO_ROOT}/tests/fixtures/browser-native-message-stream-consumer"
    if [[ ! -d "${fixture_dir}" ]]; then
        echo "FATAL: fixture missing: ${fixture_dir}" >&2
        return 1
    fi

    local missing_artifacts=0
    for required in \
        "packages/browser-core/asupersync.js" \
        "packages/browser-core/asupersync_bg.wasm" \
        "packages/browser-core/abi-metadata.json" \
        "packages/browser/dist/index.js" \
        "packages/browser/dist/index.d.ts"
    do
        if [[ ! -f "${REPO_ROOT}/${required}" ]]; then
            echo "MISSING: ${required}" >&2
            missing_artifacts=$((missing_artifacts + 1))
        fi
    done

    if [[ "${missing_artifacts}" -gt 0 ]]; then
        cat >&2 <<'EOF'
FATAL: required packaged Browser Edition artifacts are missing.

Build and stage package artifacts first, then rerun:
  PATH=/usr/bin:$PATH corepack pnpm run build

This browser-native message/stream validation intentionally runs only against built package outputs.
EOF
        return 1
    fi

    local work_dir
    work_dir="$(mktemp -d "/tmp/asupersync-browser-native-message-stream.XXXXXX")"
    local consumer_dir="${work_dir}/consumer"
    local pkg_dir="${work_dir}/packages"

    mkdir -p "${consumer_dir}" "${pkg_dir}"
    cp -R "${fixture_dir}/." "${consumer_dir}/"
    cp -R "${REPO_ROOT}/packages/browser-core" "${pkg_dir}/browser-core"
    cp -R "${REPO_ROOT}/packages/browser" "${pkg_dir}/browser"

    python3 - "${consumer_dir}/package.json" "${pkg_dir}/browser/package.json" <<'PY'
import json
import pathlib
import sys

consumer_pkg = pathlib.Path(sys.argv[1])
browser_pkg = pathlib.Path(sys.argv[2])

consumer_data = json.loads(consumer_pkg.read_text())
consumer_deps = consumer_data.setdefault("dependencies", {})
consumer_deps["@asupersync/browser"] = "file:../packages/browser"
consumer_deps["@asupersync/browser-core"] = "file:../packages/browser-core"
consumer_pkg.write_text(json.dumps(consumer_data, indent=2) + "\n")

browser_data = json.loads(browser_pkg.read_text())
browser_deps = browser_data.setdefault("dependencies", {})
browser_deps["@asupersync/browser-core"] = "file:../browser-core"
browser_pkg.write_text(json.dumps(browser_data, indent=2) + "\n")
PY

    (
        cd "${consumer_dir}"
        PATH="/usr/bin:${PATH}" npm install --no-audit --no-fund
        PATH="/usr/bin:${PATH}" npm run build
        PATH="/usr/bin:${PATH}" npm run check:bundle
        PATH="/usr/bin:${PATH}" npm run check:browser -- "${BROWSER_RUN_PATH}"
    )
}

: > "${RUN_LOG_PATH}"

if [[ "${CONTRACT_ONLY}" -eq 0 && "${DRY_RUN}" -eq 0 ]] && ! command -v "${RCH_BIN}" >/dev/null 2>&1; then
    echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
    exit 1
fi

if [[ "${CONTRACT_ONLY}" -eq 0 ]]; then
    run_proof rust_contract \
        env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 "RUSTFLAGS=-C debuginfo=0" "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_browser_native_message_stream_contract" \
        cargo test -p asupersync --test browser_native_message_stream_evidence_contract --features test-internals -- --nocapture || RUST_STATUS=$?

    {
        printf 'BROWSER_NATIVE_MESSAGE_STREAM_COMMAND label=browser_fixture timeout_sec=%s command=bash_function:%s\n' "$TIMEOUT_SEC" "run_browser_fixture"
    } >> "${RUN_LOG_PATH}"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "BROWSER_NATIVE_MESSAGE_STREAM_DRY_RUN label=browser_fixture command=bash_function:run_browser_fixture" >> "${RUN_LOG_PATH}"
        echo "BROWSER_NATIVE_MESSAGE_STREAM_COMMAND_STATUS label=browser_fixture status=0 dry_run=true" >> "${RUN_LOG_PATH}"
    else
        set +e
        (set -e; run_browser_fixture) >> "${RUN_LOG_PATH}" 2>&1
        BROWSER_STATUS=$?
        set -e
        echo "BROWSER_NATIVE_MESSAGE_STREAM_COMMAND_STATUS label=browser_fixture status=${BROWSER_STATUS}" >> "${RUN_LOG_PATH}"
    fi

    cat "${RUN_LOG_PATH}"
fi

python3 - "$REPO_ROOT" "$ARTIFACT_PATH" "$RUN_LOG_PATH" "$RUN_REPORT_PATH" "$RUN_ID" "$CONTRACT_ONLY" "$TIMEOUT_SEC" "$RUST_STATUS" "$BROWSER_STATUS" "$DRY_RUN" "$BROWSER_RUN_PATH" <<'PY' | tee -a "$RUN_LOG_PATH"
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
dry_run = sys.argv[10] == "1"
browser_run_path = Path(sys.argv[11]).resolve()

contract = json.loads(artifact_path.read_text())
required_fields = contract["required_log_fields"]
expected_scenarios = [row["scenario_id"] for row in contract["scenario_matrix"]]
scenario_contracts = {
    row["scenario_id"]: row for row in contract["scenario_matrix"]
}
log_text = run_log_path.read_text() if run_log_path.exists() else ""
browser_run = None
rows = []
drifts = []


def repo_relative(path):
    try:
        return str(path.resolve().relative_to(repo_root))
    except ValueError:
        return str(path)


def compact(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ",".join(str(item).replace(" ", "_") for item in value)
    return str(value).replace(" ", "_")


def emit(prefix, row):
    ordered = []
    for key in required_fields:
        ordered.append(f"{key}={compact(row.get(key, ''))}")
    print(prefix + " " + " ".join(ordered))


def command_log_segment(label):
    start_marker = f"BROWSER_NATIVE_MESSAGE_STREAM_COMMAND label={label} "
    start = log_text.find(start_marker)
    if start < 0:
        return ""
    next_marker = log_text.find(
        "BROWSER_NATIVE_MESSAGE_STREAM_COMMAND label=",
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


def cargo_command_has_target_dir(command):
    return "rch exec -- env " in command and re.search(r"(?:^|\s)CARGO_TARGET_DIR=", command)


for source_path in contract["source_evidence_paths"]:
    if not (repo_root / source_path).exists():
        drifts.append(f"missing_source:{source_path}")

for command in contract["validation_commands"]:
    if "cargo " in command:
        if "rch exec --" not in command:
            drifts.append(f"missing_rch:{command}")
        elif not cargo_command_has_target_dir(command):
            drifts.append(f"missing_cargo_target_dir:{command}")
    lowered = command.lower()
    for marker in ("password=", "token=", "secret=", "bearer "):
        if marker in lowered:
            drifts.append(f"sensitive_command_marker:{marker}")

fixture_source = (repo_root / contract["fixture_path"] / "src/main.ts").read_text()
if 'from "@asupersync/browser"' not in fixture_source:
    drifts.append("fixture_import_not_public_package")
for forbidden in ("packages/browser/src", "../packages/browser", "../../packages/browser"):
    if forbidden in fixture_source:
        drifts.append(f"fixture_deep_import:{forbidden}")

runner_text = (repo_root / contract["runner_script"]).read_text()
for marker in [
    '"${RCH_BIN}" exec --',
    "Remote command finished: exit=0",
    "test result: ok",
    "target/browser-native-message-stream-evidence",
    "run_report.json",
    "run.log",
    "BROWSER_NATIVE_MESSAGE_STREAM_SCENARIO",
    "--contract-only",
    "--dry-run",
    "BROWSER_NATIVE_MESSAGE_STREAM_DRY_RUN",
    "falling back to local",
    "local fallback",
    "fallback to local",
    "executing locally",
]:
    if marker not in runner_text:
        drifts.append(f"runner_missing_marker:{marker}")

effective_rust_status, rust_status_note = effective_command_status("rust_contract", rust_status)
effective_browser_status = browser_status
browser_status_note = ""
test_result_ok_count = len(re.findall(r"test result: ok", log_text))

if not contract_only and not dry_run:
    if browser_run_path.exists():
        browser_run = json.loads(browser_run_path.read_text())
    else:
        drifts.append(f"missing_browser_run:{repo_relative(browser_run_path)}")

    if effective_rust_status != 0:
        drifts.append(f"rust_contract_status:{effective_rust_status}")
    elif test_result_ok_count < 1:
        drifts.append("missing_cargo_ok_summary")

    if effective_browser_status != 0:
        drifts.append(f"browser_fixture_status:{effective_browser_status}")

    if browser_run is not None:
        if browser_run.get("status") != "ok":
            drifts.append(f"browser_run_status:{browser_run.get('status')}")
        for row in browser_run.get("rows", []):
            scenario_id = row.get("scenario_id")
            contract_row = scenario_contracts.get(scenario_id)
            if contract_row is None:
                drifts.append(f"unexpected_scenario:{scenario_id}")
                continue
            for field in required_fields:
                if field not in row:
                    drifts.append(f"{scenario_id}:missing_required_field:{field}")
            for field in [
                "api_surface",
                "capability_granted",
                "degraded_mode",
                "close_kind",
                "expected_error",
            ]:
                if row.get(field) != contract_row.get(field):
                    drifts.append(
                        f"{scenario_id}:field_drift:{field}:expected:{contract_row.get(field)!r}:actual:{row.get(field)!r}"
                    )
            if row.get("verdict") != "pass":
                drifts.append(f"{scenario_id}:fixture_verdict:{row.get('verdict')}")
            rows.append(row)
else:
    for scenario in contract["scenario_matrix"]:
        row = {
            "bead_id": contract["bead_id"],
            "scenario_id": scenario["scenario_id"],
            "host_context": scenario["host_context"],
            "api_surface": scenario["api_surface"],
            "capability_granted": scenario["capability_granted"],
            "degraded_mode": scenario["degraded_mode"],
            "bytes_sent": scenario["bytes_sent"],
            "bytes_received": scenario["bytes_received"],
            "messages_sent": scenario["messages_sent"],
            "messages_received": scenario["messages_received"],
            "close_kind": scenario["close_kind"],
            "expected_error": scenario["expected_error"],
            "actual_error": scenario["actual_error"],
            "verdict": "contract_present",
            "first_failure": "",
        }
        rows.append(row)

observed_scenarios = [row.get("scenario_id") for row in rows]
missing_scenarios = (
    [] if contract_only or dry_run else sorted(set(expected_scenarios) - set(observed_scenarios))
)
for scenario_id in missing_scenarios:
    drifts.append(f"missing_scenario:{scenario_id}")

for row in rows:
    emit(
        "BROWSER_NATIVE_MESSAGE_STREAM_SCENARIO"
        if not contract_only
        else "BROWSER_NATIVE_MESSAGE_STREAM_CONTRACT",
        row,
    )

validation_passed = not drifts and (
    contract_only or dry_run or len(set(observed_scenarios)) == len(expected_scenarios)
)
report = {
    "schema_version": contract["report_schema_version"],
    "contract_schema_version": contract["schema_version"],
    "bead_id": contract["bead_id"],
    "capability_id": contract["capability_id"],
    "run_id": run_id,
    "contract_only": contract_only,
    "dry_run": dry_run,
    "artifact_path": repo_relative(artifact_path),
    "fixture_path": contract["fixture_path"],
    "browser_run_path": repo_relative(browser_run_path) if browser_run_path.exists() else "",
    "browser_version": (browser_run or {}).get("browser_version", ""),
    "run_report_path": repo_relative(run_report_path),
    "run_log_path": repo_relative(run_log_path),
    "required_log_fields": required_fields,
    "expected_scenarios": expected_scenarios,
    "observed_scenarios": observed_scenarios,
    "missing_scenarios": missing_scenarios,
    "validation_commands": contract["validation_commands"],
    "artifact_paths": [
        "artifacts/wave2/browser_native_message_and_stream_apis_evidence.json",
        repo_relative(browser_run_path) if browser_run_path.exists() else "",
        repo_relative(run_report_path),
        repo_relative(run_log_path),
    ],
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
    "scenario_rows": rows,
}
run_report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

print(f"Run report: {repo_relative(run_report_path)}")
if not validation_passed:
    raise SystemExit(1)
PY
