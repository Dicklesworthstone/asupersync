#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONTRACT_PATH="${REPO_ROOT}/artifacts/no_mock_massive_agent_swarm_e2e_contract_v1.json"
SCENARIO_CORPUS_PATH="${REPO_ROOT}/artifacts/swarm_workload_scenario_corpus_v1.json"
OUTPUT_ROOT="${NO_MOCK_MASSIVE_AGENT_SWARM_E2E_OUTPUT_ROOT:-${REPO_ROOT}/target/no-mock-massive-agent-swarm-e2e}"
RUN_ID="${NO_MOCK_MASSIVE_AGENT_SWARM_E2E_RUN_ID:-$(date -u +%Y%m%d_%H%M%S)}"
PROFILE="${NO_MOCK_MASSIVE_AGENT_SWARM_E2E_PROFILE:-small}"
MODE="dry-run"
FEATURES="${NO_MOCK_MASSIVE_AGENT_SWARM_E2E_FEATURES:-test-internals}"
TIMEOUT_SECONDS="${NO_MOCK_MASSIVE_AGENT_SWARM_E2E_TIMEOUT_SECONDS:-1200}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_no_mock_massive_agent_swarm_e2e}"
RCH_BIN="${RCH_BIN:-rch}"

WORKER_COUNT=""
REGION_COUNT=""
TASKS_PER_REGION=""
CHANNEL_FANOUT=""
CANCELLATION_RATE=""
OBLIGATION_RATE=""

usage() {
    cat <<'USAGE'
Usage: scripts/run_no_mock_massive_agent_swarm_e2e.sh [options]

Options:
  --dry-run                    Write and print the execution manifest only.
  --execute                    Run the selected profile through RCH.
  --profile <small|medium|large|all>
                               Select the scenario profile.
  --features <features>        Cargo feature list; defaults to test-internals.
  --output-root <dir>          Directory for manifest, run.log, and run_report.json.
  --run-id <id>                Stable run id for deterministic evidence.
  --timeout-seconds <n>        Timeout wrapped around rch exec.
  --worker-count <n>           Override replay worker_count.
  --region-count <n>           Override replay region_count.
  --tasks-per-region <n>       Override replay tasks_per_region.
  --channel-fanout <n>         Override replay messages_per_task.
  --cancellation-rate <0..1>   Override cancellation policy; >0 requests cancellation.
  --obligation-rate <n>        Override replay obligations_per_task.
  -h, --help                   Show this help.
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
        --worker-count)
            WORKER_COUNT="${2:-}"
            shift 2
            ;;
        --region-count)
            REGION_COUNT="${2:-}"
            shift 2
            ;;
        --tasks-per-region)
            TASKS_PER_REGION="${2:-}"
            shift 2
            ;;
        --channel-fanout)
            CHANNEL_FANOUT="${2:-}"
            shift 2
            ;;
        --cancellation-rate)
            CANCELLATION_RATE="${2:-}"
            shift 2
            ;;
        --obligation-rate)
            OBLIGATION_RATE="${2:-}"
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
mkdir -p "${REPORT_DIR}"

GIT_COMMIT="$(git -C "${REPO_ROOT}" rev-parse --short HEAD)"
if ! git -C "${REPO_ROOT}" diff --quiet -- . ':!target' 2>/dev/null || ! git -C "${REPO_ROOT}" diff --cached --quiet -- . ':!target' 2>/dev/null; then
    GIT_COMMIT="${GIT_COMMIT}+dirty"
fi

OVERRIDES_JSON="$(python3 - "$WORKER_COUNT" "$REGION_COUNT" "$TASKS_PER_REGION" "$CHANNEL_FANOUT" "$CANCELLATION_RATE" "$OBLIGATION_RATE" <<'PY'
import json
import sys

keys = [
    "worker_count",
    "region_count",
    "tasks_per_region",
    "channel_fanout",
    "cancellation_rate",
    "obligation_rate",
]
raw = dict(zip(keys, sys.argv[1:]))
out = {}
for key, value in raw.items():
    if value == "":
        out[key] = None
        continue
    if key == "cancellation_rate":
        parsed = float(value)
        if parsed < 0.0 or parsed > 1.0:
            raise SystemExit("cancellation_rate must be between 0 and 1")
        out[key] = parsed
    else:
        parsed = int(value)
        if parsed <= 0:
            raise SystemExit(f"{key} must be a positive integer")
        out[key] = parsed
print(json.dumps(out, sort_keys=True, separators=(",", ":")))
PY
)"

DISPLAY_COMMAND="timeout ${TIMEOUT_SECONDS} env RCH_REQUIRE_REMOTE=1 ${RCH_BIN} exec -- cargo test -p asupersync --test no_mock_massive_agent_swarm_e2e_contract --features ${FEATURES} -- --nocapture"

python3 - "$CONTRACT_PATH" "$SCENARIO_CORPUS_PATH" "$MANIFEST_PATH" "$PROFILE" "$RUN_ID" "$MODE" "$FEATURES" "$TIMEOUT_SECONDS" "$GIT_COMMIT" "$OVERRIDES_JSON" "$DISPLAY_COMMAND" <<'PY'
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
overrides = json.loads(sys.argv[10])
display_command = sys.argv[11]

contract = json.loads(contract_path.read_text())
corpus = json.loads(corpus_path.read_text())
known_scenarios = {
    row["scenario_id"]: row
    for row in corpus["scenarios"]
}

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
    "schema_version": "asupersync.no-mock-massive-agent-swarm-e2e.manifest.v1",
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
    "overrides": overrides,
    "required_log_fields": contract["required_log_fields"],
    "selected_scenarios": selected,
}
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print(json.dumps(manifest, indent=2, sort_keys=True))
PY

if [[ "${MODE}" == "dry-run" ]]; then
    echo "NO_MOCK_MASSIVE_AGENT_SWARM_E2E manifest=${MANIFEST_PATH}" >&2
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
    NO_MOCK_MASSIVE_AGENT_SWARM_E2E_PROFILE="${PROFILE}"
    NO_MOCK_MASSIVE_AGENT_SWARM_E2E_OUTPUT_DIR="${REPORT_DIR}/remote-artifacts"
    NO_MOCK_MASSIVE_AGENT_SWARM_E2E_RUN_ID="${RUN_ID}"
    NO_MOCK_MASSIVE_AGENT_SWARM_E2E_FEATURES="${FEATURES}"
    NO_MOCK_MASSIVE_AGENT_SWARM_E2E_GIT_COMMIT="${GIT_COMMIT}"
    NO_MOCK_MASSIVE_AGENT_SWARM_E2E_COMMAND="cargo test -p asupersync --test no_mock_massive_agent_swarm_e2e_contract --features ${FEATURES} -- --nocapture"
    NO_MOCK_MASSIVE_AGENT_SWARM_E2E_OVERRIDES="${OVERRIDES_JSON}"
    cargo test -p asupersync --test no_mock_massive_agent_swarm_e2e_contract --features "${FEATURES}" -- --nocapture
)

{
    echo "NO_MOCK_MASSIVE_AGENT_SWARM_E2E start bead=asupersync-vssefs.6 run_id=${RUN_ID}"
    echo "repo_root=${REPO_ROOT}"
    echo "profile=${PROFILE}"
    echo "features=${FEATURES}"
    echo "git_commit=${GIT_COMMIT}"
    echo "manifest=${MANIFEST_PATH}"
    echo "run_report=${RUN_REPORT}"
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

python3 - "$CONTRACT_PATH" "$MANIFEST_PATH" "$RUN_LOG" "$RUN_REPORT" "$STATUS" <<'PY'
import json
import sys
from pathlib import Path

contract = json.loads(Path(sys.argv[1]).read_text())
manifest = json.loads(Path(sys.argv[2]).read_text())
run_log = Path(sys.argv[3])
run_report = Path(sys.argv[4])
status = int(sys.argv[5])
log_text = run_log.read_text(errors="replace")
prefix = contract["operator_evidence"]["stdout_event_prefix"]

rch_worker = ""
for line in log_text.splitlines():
    if line.startswith("RCH_WORKER="):
        rch_worker = line.split("=", 1)[1].strip()
        break
    if "Selected worker:" in line:
        after = line.split("Selected worker:", 1)[1].strip()
        rch_worker = after.split()[0]
        break
    if line.startswith("[RCH] remote "):
        rch_worker = line.split()[2]
        break

events = []
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
    if not event.get("rch_worker") or event.get("rch_worker") == "captured-by-runner":
        event["rch_worker"] = rch_worker or "unknown"
    events.append(event)

required = set(contract["required_log_fields"])
missing_fields = {
    event.get("scenario_id", f"event-{index}"): sorted(required - set(event))
    for index, event in enumerate(events)
    if required - set(event)
}
forbidden = contract["forbidden_success_markers"]
forbidden_hits = []
for event in events:
    rendered = json.dumps(event, sort_keys=True).lower()
    for marker in forbidden:
        if marker in rendered:
            forbidden_hits.append({"scenario_id": event.get("scenario_id", ""), "marker": marker})

first_failure = ""
if status != 0:
    first_failure = f"rch command exited {status}"
elif not rch_worker:
    first_failure = "missing RCH_WORKER provenance"
elif not events:
    first_failure = "no scenario event rows found in run log"
elif parse_errors:
    first_failure = f"event parse errors: {parse_errors[0]}"
elif missing_fields:
    first_failure = f"missing event fields: {missing_fields}"
elif forbidden_hits:
    first_failure = f"forbidden success marker: {forbidden_hits[0]}"

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
    "scenario_events": events,
    "missing_fields": missing_fields,
    "parse_errors": parse_errors,
    "forbidden_marker_hits": forbidden_hits,
    "status": status,
    "validation_passed": first_failure == "",
    "first_failure": first_failure,
}
run_report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
if first_failure:
    raise SystemExit(1)
PY

echo "NO_MOCK_MASSIVE_AGENT_SWARM_E2E report=${RUN_REPORT}" | tee -a "${RUN_LOG}"
