#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURE="${LARGE_HOST_TOPOLOGY_CORPUS_FIXTURE:-${REPO_ROOT}/artifacts/large_host_topology_corpus_v1.json}"
OUTPUT_ROOT="${LARGE_HOST_TOPOLOGY_CORPUS_OUTPUT_ROOT:-${REPO_ROOT}/target/large-host-topology-corpus}"
RUN_ID="$(date -u +%Y%m%d_%H%M%S)"
GENERATED_AT="2026-06-06T04:05:00Z"

usage() {
    cat <<'USAGE'
Usage: scripts/run_large_host_topology_corpus_e2e.sh [options]

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

python3 "${REPO_ROOT}/scripts/large_host_topology_corpus.py" \
    --fixture "${FIXTURE}" \
    --repo-path "${REPO_ROOT}" \
    --generated-at "${GENERATED_AT}" \
    --artifact-path "${JSON_REPORT}" \
    --output json \
    --output-path "${JSON_REPORT}"

python3 "${REPO_ROOT}/scripts/large_host_topology_corpus.py" \
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
    "profile_id",
    "profile_family",
    "status",
    "physical_cores",
    "memory_gib",
    "numa_nodes",
    "rch_slots",
    "fallback_action",
    "artifact_path",
    "first_failure",
]

def clean(value):
    text = "" if value is None else str(value)
    return re.sub(r"\s+", "_", text.strip())

lines = []
for row in report["profile_receipts"]:
    log_row = {
        "bead_id": report["bead_id"],
        "profile_id": row["profile_id"],
        "profile_family": row["profile_family"],
        "status": row["status"],
        "physical_cores": row["physical_cores"],
        "memory_gib": row["memory_gib"],
        "numa_nodes": row["numa_nodes"],
        "rch_slots": row["rch_slots"],
        "fallback_action": row["fallback_action"],
        "artifact_path": str(report_path),
        "first_failure": row["first_failure"],
    }
    line = " ".join(f"{field}={clean(log_row.get(field, ''))}" for field in required)
    lines.append(line)
    print(line)

summary = (
    "bead_id={bead_id} profile_id=summary profile_family=all status={status} "
    "physical_cores=0 memory_gib=0 numa_nodes=0 rch_slots=0 "
    "fallback_action=review_topology_contract artifact_path={artifact_path} first_failure={first_failure}"
).format(
    bead_id=report["bead_id"],
    status="pass" if report["operator_summary"]["validation_passed"] else "blocked",
    artifact_path=report_path,
    first_failure=report["operator_summary"]["first_failure"],
)
lines.append(summary)
print(summary)
log_path.write_text("\n".join(lines) + "\n")

if not report["operator_summary"]["validation_passed"]:
    raise SystemExit(1)
PY
