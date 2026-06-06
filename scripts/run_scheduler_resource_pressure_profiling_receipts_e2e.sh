#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURE="${SCHEDULER_RESOURCE_PRESSURE_PROFILING_FIXTURE:-${REPO_ROOT}/artifacts/scheduler_resource_pressure_profiling_receipts_v1.json}"
OUTPUT_ROOT="${SCHEDULER_RESOURCE_PRESSURE_PROFILING_OUTPUT_ROOT:-${REPO_ROOT}/target/scheduler-resource-pressure-profiling-receipts}"
RUN_ID="$(date -u +%Y%m%d_%H%M%S)"
GENERATED_AT="2026-06-06T02:45:00Z"

usage() {
    cat <<'USAGE'
Usage: scripts/run_scheduler_resource_pressure_profiling_receipts_e2e.sh [options]

Options:
  --fixture <path>        Contract or fixture JSON path.
  --output-root <dir>     Directory for run artifacts.
  --run-id <id>           Deterministic run id.
  --generated-at <ts>     Deterministic generated_at timestamp.
  -h, --help              Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fixture)
            FIXTURE="${2:-}"
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
        --generated-at)
            GENERATED_AT="${2:-}"
            shift 2
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
JSON_REPORT="${REPORT_DIR}/run_report.json"
MARKDOWN_REPORT="${REPORT_DIR}/run_report.md"
RUN_LOG="${REPORT_DIR}/run.log"

mkdir -p "${REPORT_DIR}"

python3 "${REPO_ROOT}/scripts/scheduler_resource_pressure_profiling_receipts.py" \
    --fixture "${FIXTURE}" \
    --repo-path "${REPO_ROOT}" \
    --generated-at "${GENERATED_AT}" \
    --artifact-path "${JSON_REPORT}" \
    --output json \
    --output-path "${JSON_REPORT}"

python3 "${REPO_ROOT}/scripts/scheduler_resource_pressure_profiling_receipts.py" \
    --fixture "${FIXTURE}" \
    --repo-path "${REPO_ROOT}" \
    --generated-at "${GENERATED_AT}" \
    --artifact-path "${MARKDOWN_REPORT}" \
    --output markdown \
    --output-path "${MARKDOWN_REPORT}"

python3 - "${JSON_REPORT}" "${RUN_LOG}" <<'PY'
import json
import re
import sys
from pathlib import Path

report_path = Path(sys.argv[1])
log_path = Path(sys.argv[2])
report = json.loads(report_path.read_text())
required = report.get("required_log_fields") or [
    "bead_id",
    "scenario_id",
    "scenario_family",
    "status",
    "data_hash",
    "top_hot_path",
    "memory_ceiling_mb",
    "operator_action",
    "artifact_path",
    "first_failure",
]

def clean(value):
    text = "" if value is None else str(value)
    return re.sub(r"\s+", "_", text.strip())

lines = []
for row in report["scenario_receipts"]:
    log_row = {
        "bead_id": report["bead_id"],
        "scenario_id": row["scenario_id"],
        "scenario_family": row["scenario_family"],
        "status": row["status"],
        "data_hash": row["data_hash"],
        "top_hot_path": row["top_hot_path"],
        "memory_ceiling_mb": row["memory_ceiling_mb"],
        "operator_action": row["operator_action"],
        "artifact_path": str(report_path),
        "first_failure": row["first_failure"],
    }
    line = " ".join(f"{field}={clean(log_row.get(field, ''))}" for field in required)
    lines.append(line)
    print(line)

summary = (
    "bead_id={bead_id} scenario_id=summary scenario_family=all status={status} "
    "data_hash={source_digest} top_hot_path=all memory_ceiling_mb=0 "
    "operator_action=review_contract_receipts artifact_path={artifact_path} first_failure={first_failure}"
).format(
    bead_id=report["bead_id"],
    status="pass" if report["operator_summary"]["validation_passed"] else "blocked",
    source_digest=report["source_digest"],
    artifact_path=report_path,
    first_failure=report["operator_summary"]["first_failure"],
)
lines.append(summary)
print(summary)
log_path.write_text("\n".join(lines) + "\n")

if not report["operator_summary"]["validation_passed"]:
    raise SystemExit(1)
PY
