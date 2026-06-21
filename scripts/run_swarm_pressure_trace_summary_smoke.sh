#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_ROOT="${SWARM_PRESSURE_TRACE_SUMMARY_OUTPUT_ROOT:-${REPO_ROOT}/target/swarm-pressure-trace-summary}"
RUN_ID="${SWARM_PRESSURE_TRACE_SUMMARY_RUN_ID:-$(date -u +%Y%m%d_%H%M%S)}"
RCH_BIN="${RCH_BIN:-rch}"
REMOTE_REQUIRED="${RCH_REQUIRE_REMOTE:-1}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/rch_target_swarm_pressure_trace_summary}"
CARGO_FEATURES="${SWARM_PRESSURE_TRACE_SUMMARY_FEATURES:-}"

usage() {
    cat <<'USAGE'
Usage: scripts/run_swarm_pressure_trace_summary_smoke.sh [options]

Runs the focused swarm pressure trace summary contract tests with detailed,
stable logs suitable for bead closeout evidence.

Options:
  --output-root <dir>   Directory for run.log and run_report.json.
  --run-id <id>         Stable run id for deterministic test harnesses.
  --features <list>     Cargo feature list for temporary frontier isolation.
  --local               Run cargo directly instead of rch.
  --list                List smoke targets and exit.
  -h, --help            Show this help.
USAGE
}

USE_LOCAL=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-root)
            OUTPUT_ROOT="${2:-}"
            shift 2
            ;;
        --run-id)
            RUN_ID="${2:-}"
            shift 2
            ;;
        --features)
            CARGO_FEATURES="${2:-}"
            shift 2
            ;;
        --local)
            USE_LOCAL=1
            shift
            ;;
        --list)
            printf '%s\n' 'swarm_pressure_trace_summary_contract'
            exit 0
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
RUN_LOG="${REPORT_DIR}/run.log"
RUN_REPORT="${REPORT_DIR}/run_report.json"
mkdir -p "${REPORT_DIR}"

echo "bead_id=asupersync-vssefs.7 run_id=${RUN_ID}" | tee "${RUN_LOG}"
echo "repo_root=${REPO_ROOT}" | tee -a "${RUN_LOG}"
echo "output_root=${OUTPUT_ROOT}" | tee -a "${RUN_LOG}"
echo "cargo_target_dir=${CARGO_TARGET_DIR}" | tee -a "${RUN_LOG}"
echo "cargo_features=${CARGO_FEATURES:-default}" | tee -a "${RUN_LOG}"

CARGO_ARGS=(test -p asupersync --test swarm_pressure_trace_summary_contract)
if [[ -n "${CARGO_FEATURES}" ]]; then
    CARGO_ARGS+=(--features "${CARGO_FEATURES}")
fi
CARGO_ARGS+=(-- --nocapture)

if [[ "${USE_LOCAL}" -eq 1 ]]; then
    COMMAND=(cargo "${CARGO_ARGS[@]}")
    echo "executor=local" | tee -a "${RUN_LOG}"
else
    COMMAND=(env "RCH_REQUIRE_REMOTE=${REMOTE_REQUIRED}" "${RCH_BIN}" exec -- env "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}" cargo "${CARGO_ARGS[@]}")
    echo "executor=rch remote_required=${REMOTE_REQUIRED}" | tee -a "${RUN_LOG}"
fi

echo "command=${COMMAND[*]}" | tee -a "${RUN_LOG}"

set +e
(
    cd "${REPO_ROOT}"
    "${COMMAND[@]}"
) 2>&1 | tee -a "${RUN_LOG}"
STATUS=${PIPESTATUS[0]}
set -e

python3 - "$RUN_ID" "$RUN_LOG" "$RUN_REPORT" "$STATUS" "$USE_LOCAL" <<'PY'
import json
import sys
from pathlib import Path

run_id = sys.argv[1]
run_log = Path(sys.argv[2])
run_report = Path(sys.argv[3])
status = int(sys.argv[4])
use_local = sys.argv[5] == "1"
log_text = run_log.read_text()

required_markers = [
    "Swarm Pressure Trace Summary",
    "missing_obligation_fields_never_render_false_green",
    "pressure_lab_artifact_summarizes_throttle_but_stays_incomplete_without_obligations",
]
missing_markers = [marker for marker in required_markers if marker not in log_text]

report = {
    "schema_version": "asupersync.swarm-pressure-trace-summary-smoke.v1",
    "bead_id": "asupersync-vssefs.7",
    "run_id": run_id,
    "executor": "local" if use_local else "rch",
    "cargo_features": next(
        (line.split("=", 1)[1] for line in log_text.splitlines() if line.startswith("cargo_features=")),
        "unknown",
    ),
    "status": status,
    "run_log": str(run_log),
    "required_markers": required_markers,
    "missing_markers": missing_markers,
    "validation_passed": status == 0 and not missing_markers,
}
run_report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

if not report["validation_passed"]:
    raise SystemExit(1)
PY
