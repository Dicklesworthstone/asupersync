#!/usr/bin/env bash
# AppSpec v1 reference-journey e2e runner (bead asupersync-idea-wizard-fifth-wave-3gaiun.2.4, [APPSPEC][A4]).
#
# Runs the runnable reference journey (examples/appspec_reference_journey.rs) and
# persists its e2e artifacts to FILES (the example streams them to stdout under
# `# events.ndjson` / `# summary.json` / `# topology.txt` section markers), then
# validates the contract a CI gate or human can diff:
#   - events.ndjson : structured lifecycle log (one JSON object per line)
#   - summary.json  : aggregate (fingerprints, deterministic_replay, ergonomics)
#   - topology.txt  : byte-stable generated topology report
#
# Validation is remote-required: the journey compiles+runs through `rch exec`
# (no local cargo fallback). Use --from-output <file> to re-validate a previously
# captured stdout without recompiling (offline contract check).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_ROOT="${APPSPEC_JOURNEY_OUTPUT_ROOT:-${REPO_ROOT}/target/e2e-results/appspec_reference_journey}"
RUN_ID="$(date -u +%Y%m%d_%H%M%S)"
TIMEOUT_SEC="${APPSPEC_JOURNEY_TIMEOUT_SEC:-900}"
# Empty by default: let rch pick its warm shared worker target (a custom dir
# forces a cold full-lib rebuild). Set --target-dir to pin one.
TARGET_DIR="${CARGO_TARGET_DIR:-}"
RCH_BIN="${RCH_BIN:-rch}"
FROM_OUTPUT=""

usage() {
    cat <<'USAGE'
Usage: scripts/run_appspec_reference_journey_e2e.sh [options]

Runs examples/appspec_reference_journey.rs via rch, splits its stdout into
events.ndjson / summary.json / topology.txt under the run directory, and
validates the e2e contract.

Options:
  --output-root <dir>   Root for run_<id>/ artifacts (default: target/e2e-results/...).
  --run-id <id>         Deterministic run id (default: UTC timestamp).
  --timeout-sec <sec>   Wall-clock timeout for the rch cargo run.
  --target-dir <dir>    CARGO_TARGET_DIR used by rch.
  --rch-bin <path>      rch binary (default: rch).
  --from-output <file>  Skip cargo; split+validate this captured example stdout.
  -h, --help            Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-root) OUTPUT_ROOT="${2:-}"; shift 2 ;;
        --run-id)      RUN_ID="${2:-}"; shift 2 ;;
        --timeout-sec) TIMEOUT_SEC="${2:-}"; shift 2 ;;
        --target-dir)  TARGET_DIR="${2:-}"; shift 2 ;;
        --rch-bin)     RCH_BIN="${2:-}"; shift 2 ;;
        --from-output) FROM_OUTPUT="${2:-}"; shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}"
RAW_STDOUT="${RUN_DIR}/example_stdout.txt"
RUN_LOG="${RUN_DIR}/run.log"
mkdir -p "${RUN_DIR}"
: > "${RUN_LOG}"

CARGO_STATUS=0
if [[ -n "${FROM_OUTPUT}" ]]; then
    if [[ ! -f "${FROM_OUTPUT}" ]]; then
        echo "FATAL: --from-output file not found: ${FROM_OUTPUT}" >&2
        exit 1
    fi
    cp "${FROM_OUTPUT}" "${RAW_STDOUT}"
    echo "APPSPEC_JOURNEY from_output=${FROM_OUTPUT} (cargo skipped)" >> "${RUN_LOG}"
else
    if ! command -v "${RCH_BIN}" >/dev/null 2>&1; then
        echo "FATAL: rch is required (remote-only validation) and was not found at: ${RCH_BIN}" >&2
        exit 1
    fi
    RCH_COMMAND=("${RCH_BIN}" exec --)
    if [[ -n "${TARGET_DIR}" ]]; then
        RCH_COMMAND+=(env "CARGO_TARGET_DIR=${TARGET_DIR}")
    fi
    RCH_COMMAND+=(cargo run --quiet --example appspec_reference_journey)
    {
        printf 'APPSPEC_JOURNEY_COMMAND timeout_sec=%s command=' "${TIMEOUT_SEC}"
        printf '%q ' "${RCH_COMMAND[@]}"
        printf '\n'
    } >> "${RUN_LOG}"
    set +e
    timeout "${TIMEOUT_SEC}" "${RCH_COMMAND[@]}" > "${RAW_STDOUT}" 2>> "${RUN_LOG}"
    CARGO_STATUS=$?
    set -e
    echo "APPSPEC_JOURNEY_COMMAND_STATUS status=${CARGO_STATUS}" >> "${RUN_LOG}"
    if [[ "${CARGO_STATUS}" -ne 0 ]]; then
        echo "FATAL: example run failed (status=${CARGO_STATUS}); see ${RUN_LOG}" >&2
        exit "${CARGO_STATUS}"
    fi
fi

# Split the marker-delimited stdout into the three artifact files.
awk -v outdir="${RUN_DIR}" '
    /^# events\.ndjson$/ { cur = outdir "/events.ndjson"; printf "" > cur; next }
    /^# summary\.json$/  { cur = outdir "/summary.json";  printf "" > cur; next }
    /^# topology\.txt$/  { cur = outdir "/topology.txt";  printf "" > cur; next }
    { if (cur != "") print >> cur }
' "${RAW_STDOUT}"

for f in events.ndjson summary.json topology.txt; do
    if [[ ! -s "${RUN_DIR}/${f}" ]]; then
        echo "FATAL: expected non-empty artifact ${f} not produced from example stdout" >&2
        exit 1
    fi
done

# Validate the e2e contract over the persisted artifacts.
python3 - "${RUN_DIR}" <<'PY'
import json, sys, pathlib

run_dir = pathlib.Path(sys.argv[1])
errors = []

events = []
for i, line in enumerate((run_dir / "events.ndjson").read_text().splitlines(), start=1):
    line = line.strip()
    if not line:
        continue
    try:
        events.append(json.loads(line))
    except json.JSONDecodeError as exc:
        errors.append(f"events.ndjson line {i} is not valid JSON: {exc}")
kinds = [e.get("event") for e in events]
for required in ("manifest_compiled", "replay_verified", "failure_rehearsal"):
    if required not in kinds:
        errors.append(f"events.ndjson missing required event '{required}'")
if kinds.count("seed_run") < 3:
    errors.append(f"events.ndjson expected >=3 seed_run events, got {kinds.count('seed_run')}")
for e in events:
    if e.get("event") == "seed_run" and e.get("orphan_tasks") != 0:
        errors.append(f"seed_run seed={e.get('seed')} reported orphan_tasks={e.get('orphan_tasks')}")
    if e.get("event") == "failure_rehearsal" and e.get("outcome") != "fail_closed":
        errors.append(f"failure_rehearsal outcome={e.get('outcome')} (expected fail_closed)")

summary = json.loads((run_dir / "summary.json").read_text())
if summary.get("deterministic_replay") is not True:
    errors.append(f"summary.deterministic_replay={summary.get('deterministic_replay')} (expected true)")
if summary.get("quiescent") is not True:
    errors.append(f"summary.quiescent={summary.get('quiescent')} (expected true)")
if summary.get("orphan_tasks") != 0:
    errors.append(f"summary.orphan_tasks={summary.get('orphan_tasks')} (expected 0)")
if "fail_closed" not in str(summary.get("failure_rehearsal", "")):
    errors.append(f"summary.failure_rehearsal={summary.get('failure_rehearsal')!r} (expected fail_closed)")
fps = summary.get("trace_fingerprints", [])
if not fps:
    errors.append("summary.trace_fingerprints is empty")
elif len(set(fps)) != 1:
    errors.append(f"summary.trace_fingerprints not deterministic across seeds: {fps}")
if not isinstance(summary.get("ergonomics"), dict):
    errors.append("summary.ergonomics missing (line-count/ergonomics note)")

topology = (run_dir / "topology.txt").read_text()
if "AppSpec v1 generated topology" not in topology:
    errors.append("topology.txt missing the generated-topology header")

report = {
    "run_dir": str(run_dir),
    "events": len(events),
    "seed_runs": kinds.count("seed_run"),
    "deterministic_replay": summary.get("deterministic_replay"),
    "trace_fingerprints": fps,
    "failure_rehearsal": summary.get("failure_rehearsal"),
    "ok": not errors,
    "errors": errors,
}
(run_dir / "run_report.json").write_text(json.dumps(report, indent=2) + "\n")

if errors:
    print("APPSPEC_JOURNEY_E2E FAIL", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)
    sys.exit(1)
print(
    "APPSPEC_JOURNEY_E2E OK: "
    f"{len(events)} events, {kinds.count('seed_run')} seeds quiescent, "
    f"deterministic_replay={summary.get('deterministic_replay')}, "
    f"fingerprint={fps[0]}, fail-closed rehearsal verified"
)
print(f"  artifacts: {run_dir}/{{events.ndjson,summary.json,topology.txt,run_report.json}}")
PY
