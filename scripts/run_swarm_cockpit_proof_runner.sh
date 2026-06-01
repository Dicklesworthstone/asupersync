#!/usr/bin/env bash
# run_swarm_cockpit_proof_runner.sh — No-mock cockpit proof runner (br-asupersync-vssefs.9.7).
#
# Consumes the swarm scenario corpus, executes a bounded real scenario through
# live Asupersync lab-runtime surfaces via RCH, and writes the operator cockpit
# report bundle (manifest, run log, run report, cockpit report JSON + text).
#
# Dry-run mode writes the manifest and exits without invoking cargo or rch.
# Execute mode requires RCH_REQUIRE_REMOTE=1 and fails closed on local fallback,
# missing provenance, missing events, or any non-pass closeout outcome.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONTRACT_PATH="${REPO_ROOT}/artifacts/swarm_cockpit_proof_runner_contract_v1.json"
SCENARIO_CORPUS_PATH="${REPO_ROOT}/artifacts/swarm_workload_scenario_corpus_v1.json"
OUTPUT_ROOT="${SWARM_COCKPIT_PROOF_OUTPUT_ROOT:-${REPO_ROOT}/target/swarm-cockpit-proof-runner}"
RUN_ID="${SWARM_COCKPIT_PROOF_RUN_ID:-$(date -u +%Y%m%d_%H%M%S)}"
PROFILE="${SWARM_COCKPIT_PROOF_PROFILE:-small}"
MODE="dry-run"
FEATURES="${SWARM_COCKPIT_PROOF_FEATURES:-test-internals}"
TIMEOUT_SECONDS="${SWARM_COCKPIT_PROOF_TIMEOUT_SECONDS:-1800}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_swarm_cockpit_proof_runner}"
RCH_BIN="${RCH_BIN:-rch}"

usage() {
    cat <<'USAGE'
Usage: scripts/run_swarm_cockpit_proof_runner.sh [options]

Options:
  --dry-run              Write and print the execution manifest only (default).
  --execute              Run the selected profile through RCH and emit the
                         cockpit report bundle.
  --profile <small|medium|large|all>
                         Select the scenario profile (default: small).
  --features <features>  Cargo feature list (default: test-internals).
  --output-root <dir>    Directory for manifest, run.log, run_report.json,
                         cockpit_report.json, and cockpit_report.txt.
  --run-id <id>          Stable run id for deterministic evidence.
  --timeout-seconds <n>  Timeout wrapped around rch exec (default: 1800).
  -h, --help             Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            MODE="dry-run"
            shift
            ;;
        --execute)
            MODE="execute"
            shift
            ;;
        --profile)
            PROFILE="${2:-}"
            shift 2
            ;;
        --features)
            FEATURES="${2:-}"
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
        --timeout-seconds)
            TIMEOUT_SECONDS="${2:-}"
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

if [[ -z "${PROFILE}" || -z "${FEATURES}" || -z "${TIMEOUT_SECONDS}" ]]; then
    echo "FATAL: --profile, --features, and --timeout-seconds must be nonempty" >&2
    exit 2
fi

REPORT_DIR="${OUTPUT_ROOT}/run_${RUN_ID}"
MANIFEST_PATH="${REPORT_DIR}/manifest.json"
RUN_LOG="${REPORT_DIR}/run.log"
RUN_REPORT="${REPORT_DIR}/run_report.json"
COCKPIT_REPORT_JSON="${REPORT_DIR}/cockpit_report.json"
COCKPIT_REPORT_TEXT="${REPORT_DIR}/cockpit_report.txt"
mkdir -p "${REPORT_DIR}"

GIT_COMMIT="$(git -C "${REPO_ROOT}" rev-parse --short HEAD)"
if ! git -C "${REPO_ROOT}" diff --quiet -- . ':!target' 2>/dev/null || ! git -C "${REPO_ROOT}" diff --cached --quiet -- . ':!target' 2>/dev/null; then
    GIT_COMMIT="${GIT_COMMIT}+dirty"
fi

CARGO_TEST_COMMAND="cargo test -p asupersync --test swarm_cockpit_proof_runner_contract --features ${FEATURES} -- --nocapture"
# The full replayable command: this exact string is what the proof lane and
# operator evidence carry, so it must include the RCH wrapper and target dir.
DISPLAY_COMMAND="timeout ${TIMEOUT_SECONDS} env RCH_REQUIRE_REMOTE=1 ${RCH_BIN} exec -- env CARGO_TARGET_DIR=${CARGO_TARGET_DIR} ${CARGO_TEST_COMMAND}"

python3 - "$CONTRACT_PATH" "$SCENARIO_CORPUS_PATH" "$MANIFEST_PATH" "$PROFILE" "$RUN_ID" "$MODE" "$FEATURES" "$TIMEOUT_SECONDS" "$GIT_COMMIT" "$DISPLAY_COMMAND" <<'PY'
import json
import sys
from pathlib import Path

contract_path = Path(sys.argv[1])
corpus_path = Path(sys.argv[2])
manifest_path = Path(sys.argv[3])
profile = sys.argv[4]
run_id = sys.argv[5]
mode = sys.argv[6]
features = sys.argv[7]
timeout_seconds = int(sys.argv[8])
git_commit = sys.argv[9]
display_command = sys.argv[10]

contract = json.loads(contract_path.read_text())
corpus = json.loads(corpus_path.read_text())
known_scenarios = {row["scenario_id"]: row for row in corpus["scenarios"]}

if profile != "all" and profile not in {"small", "medium", "large"}:
    raise SystemExit("profile must be one of small, medium, large, all")

selected = [
    row
    for row in contract["scenario_matrix"]
    if profile == "all" or row["profile"] == profile
]
if not selected:
    raise SystemExit(f"profile {profile} selected no scenarios")

for row in selected:
    source_id = row["source_scenario_id"]
    if source_id not in known_scenarios:
        raise SystemExit(f"unknown source scenario {source_id}")

manifest = {
    "schema_version": contract["manifest_schema_version"],
    "contract_version": contract["contract_version"],
    "bead_id": contract["bead_id"],
    "run_id": run_id,
    "mode": mode,
    "profile": profile,
    "features": features,
    "timeout_seconds": timeout_seconds,
    "git_commit": git_commit,
    "remote_required": True,
    "local_fallback_allowed": contract["execution_policy"]["local_fallback_allowed"],
    "command": display_command,
    "required_log_fields": contract["required_log_fields"],
    "forbidden_success_markers": contract["forbidden_success_markers"],
    "stdout_event_prefix": contract["operator_evidence"]["stdout_event_prefix"],
    "selected_scenarios": selected,
    "cockpit_report_schema_version": contract["cockpit_report_schema_version"],
}
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print(json.dumps(manifest, indent=2, sort_keys=True))
PY

if [[ "${MODE}" == "dry-run" ]]; then
    echo "SWARM_COCKPIT_PROOF manifest=${MANIFEST_PATH}" >&2
    exit 0
fi

if [[ "${MODE}" != "execute" ]]; then
    echo "FATAL: unsupported mode: ${MODE}" >&2
    exit 2
fi

COMMAND=(
    timeout "${TIMEOUT_SECONDS}"
    env RCH_REQUIRE_REMOTE=1 "${RCH_BIN}" exec --
    env
    CARGO_INCREMENTAL=0
    CARGO_PROFILE_TEST_DEBUG=0
    RUSTFLAGS="-C debuginfo=0"
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR}"
    SWARM_COCKPIT_PROOF_REMOTE=1
    SWARM_COCKPIT_PROOF_PROFILE="${PROFILE}"
    SWARM_COCKPIT_PROOF_OUTPUT_DIR="${REPORT_DIR}"
    SWARM_COCKPIT_PROOF_RUN_ID="${RUN_ID}"
    SWARM_COCKPIT_PROOF_FEATURES="${FEATURES}"
    SWARM_COCKPIT_PROOF_GIT_COMMIT="${GIT_COMMIT}"
    SWARM_COCKPIT_PROOF_TARGET_DIR="${CARGO_TARGET_DIR}"
    SWARM_COCKPIT_PROOF_COMMAND="${DISPLAY_COMMAND}"
    cargo test -p asupersync --test swarm_cockpit_proof_runner_contract --features "${FEATURES}" -- --nocapture
)

{
    echo "SWARM_COCKPIT_PROOF start bead=asupersync-vssefs.9.7 run_id=${RUN_ID}"
    echo "repo_root=${REPO_ROOT}"
    echo "profile=${PROFILE}"
    echo "features=${FEATURES}"
    echo "git_commit=${GIT_COMMIT}"
    echo "manifest=${MANIFEST_PATH}"
    echo "run_report=${RUN_REPORT}"
    echo "cockpit_report_json=${COCKPIT_REPORT_JSON}"
    echo "cockpit_report_text=${COCKPIT_REPORT_TEXT}"
    echo "remote_required=1"
    echo "cargo_target_dir=${CARGO_TARGET_DIR}"
    echo "command=${COMMAND[*]}"
} | tee "${RUN_LOG}"

set +e
(
    cd "${REPO_ROOT}"
    "${COMMAND[@]}"
) 2>&1 | tee -a "${RUN_LOG}"
STATUS=${PIPESTATUS[0]}
set -e

python3 - "$CONTRACT_PATH" "$MANIFEST_PATH" "$RUN_LOG" "$RUN_REPORT" "$COCKPIT_REPORT_JSON" "$COCKPIT_REPORT_TEXT" "$STATUS" <<'PY'
import json
import sys
from pathlib import Path

contract = json.loads(Path(sys.argv[1]).read_text())
manifest = json.loads(Path(sys.argv[2]).read_text())
run_log = Path(sys.argv[3])
run_report = Path(sys.argv[4])
cockpit_report_json = Path(sys.argv[5])
cockpit_report_text = Path(sys.argv[6])
status = int(sys.argv[7])
log_text = run_log.read_text(errors="replace")
prefix = contract["operator_evidence"]["stdout_event_prefix"]

# Fail closed on any rch local-fallback marker.
local_fallback = any(
    line.startswith("[RCH] local (") or "falling back to local" in line
    for line in log_text.splitlines()
)

rch_worker = ""
for line in log_text.splitlines():
    if line.startswith("RCH_WORKER="):
        rch_worker = line.split("=", 1)[1].strip()
        break
    if "Selected worker:" in line:
        rch_worker = line.split("Selected worker:", 1)[1].strip().split()[0]
        break
    if line.startswith("[RCH] remote "):
        rch_worker = line.split()[2]
        break

scenario_events = []
cockpit_reports = {}
cockpit_texts = {}
parse_errors = []
for line in log_text.splitlines():
    if prefix not in line:
        continue
    payload = line.split(prefix, 1)[1].strip()
    try:
        event = json.loads(payload)
    except json.JSONDecodeError as exc:
        parse_errors.append(f"{payload[:80]}: {exc}")
        continue
    kind = event.get("kind", "scenario_row")
    scenario_id = event.get("scenario_id", "")
    if kind == "cockpit_report":
        cockpit_reports[scenario_id] = event.get("report")
        continue
    if kind == "cockpit_text":
        cockpit_texts[scenario_id] = event.get("text", "")
        continue
    if not event.get("rch_worker") or event.get("rch_worker") == "captured-by-runner":
        event["rch_worker"] = rch_worker or "unknown"
    scenario_events.append(event)

required = set(contract["required_log_fields"])
missing_fields = {
    event.get("scenario_id", f"event-{index}"): sorted(required - set(event))
    for index, event in enumerate(scenario_events)
    if required - set(event)
}
forbidden = contract["forbidden_success_markers"]
forbidden_hits = []
for event in scenario_events:
    rendered = json.dumps(event, sort_keys=True).lower()
    for marker in forbidden:
        if marker in rendered:
            forbidden_hits.append({"scenario_id": event.get("scenario_id", ""), "marker": marker})

# Closeout policy: every executed scenario row must report a passing cockpit
# outcome when this script supplied real RCH provenance.
non_pass_rows = [
    {"scenario_id": event.get("scenario_id", ""), "cockpit_outcome": event.get("cockpit_outcome", "")}
    for event in scenario_events
    if event.get("proof_status") != "pass" or event.get("cockpit_outcome") != "pass"
]
missing_bundles = [
    event.get("scenario_id", "")
    for event in scenario_events
    if event.get("scenario_id", "") not in cockpit_reports
    or event.get("scenario_id", "") not in cockpit_texts
]

first_failure = ""
if status != 0:
    first_failure = f"rch command exited {status}"
elif local_fallback:
    first_failure = "rch local fallback detected; remote execution is required"
elif not rch_worker:
    first_failure = "missing RCH worker provenance"
elif not scenario_events:
    first_failure = "no scenario event rows found in run log"
elif parse_errors:
    first_failure = f"event parse errors: {parse_errors[0]}"
elif missing_fields:
    first_failure = f"missing event fields: {missing_fields}"
elif forbidden_hits:
    first_failure = f"forbidden success marker: {forbidden_hits[0]}"
elif non_pass_rows:
    first_failure = f"non-pass cockpit outcome under remote provenance: {non_pass_rows[0]}"
elif missing_bundles:
    first_failure = f"missing cockpit bundle events for: {missing_bundles[0]}"

# Write the cockpit bundle extracted from the remote run's stdout events.
written_bundles = []
for scenario_id, report in cockpit_reports.items():
    if report is None:
        continue
    cockpit_report_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    written_bundles.append(str(cockpit_report_json))
    text = cockpit_texts.get(scenario_id, "")
    if text:
        cockpit_report_text.write_text(text + "\n")
        written_bundles.append(str(cockpit_report_text))
    break

report = {
    "schema_version": contract["run_report_schema_version"],
    "contract_version": contract["contract_version"],
    "bead_id": contract["bead_id"],
    "run_id": manifest["run_id"],
    "profile": manifest["profile"],
    "mode": manifest["mode"],
    "executor": "rch",
    "remote_required": True,
    "local_fallback_allowed": False,
    "git_commit": manifest["git_commit"],
    "feature_set": manifest["features"],
    "command": manifest["command"],
    "rch_worker": rch_worker,
    "manifest_path": str(Path(sys.argv[2])),
    "run_log_path": str(run_log),
    "cockpit_report_json_path": str(cockpit_report_json),
    "cockpit_report_text_path": str(cockpit_report_text),
    "written_bundle_paths": written_bundles,
    "scenario_events": scenario_events,
    "missing_fields": missing_fields,
    "parse_errors": parse_errors,
    "forbidden_marker_hits": forbidden_hits,
    "non_pass_rows": non_pass_rows,
    "status": status,
    "validation_passed": first_failure == "",
    "first_failure": first_failure,
}
run_report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
if first_failure:
    raise SystemExit(1)
PY

echo "SWARM_COCKPIT_PROOF report=${RUN_REPORT}" | tee -a "${RUN_LOG}"
echo "SWARM_COCKPIT_PROOF cockpit_report=${COCKPIT_REPORT_JSON}" | tee -a "${RUN_LOG}"
