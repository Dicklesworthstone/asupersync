#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURE="${SECOND_WAVE_CERTIFICATION_FIXTURE:-${REPO_ROOT}/artifacts/second_wave_swarm_control_loop_certification_v1.json}"
OUTPUT_ROOT="${SECOND_WAVE_CERTIFICATION_OUTPUT_ROOT:-${REPO_ROOT}/target/second-wave-swarm-control-loop-certification}"
RUN_ID="local-check"
GENERATED_AT="2026-06-06T11:15:00Z"

usage() {
    cat <<'USAGE'
Usage: scripts/run_second_wave_swarm_control_loop_certification_e2e.sh [options]

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
JSON_REPORT="${REPORT_DIR}/certification.json"
MARKDOWN_REPORT="${REPORT_DIR}/certification.md"
RUN_LOG="${REPORT_DIR}/certification.log"
SUMMARY_PATH="${REPORT_DIR}/summary.json"

mkdir -p "${REPORT_DIR}"

python3 "${REPO_ROOT}/scripts/second_wave_swarm_control_loop_certification.py" \
    --fixture "${FIXTURE}" \
    --repo-root "${REPO_ROOT}" \
    --generated-at "${GENERATED_AT}" \
    --output json > "${JSON_REPORT}"

python3 "${REPO_ROOT}/scripts/second_wave_swarm_control_loop_certification.py" \
    --fixture "${FIXTURE}" \
    --repo-root "${REPO_ROOT}" \
    --generated-at "${GENERATED_AT}" \
    --output markdown > "${MARKDOWN_REPORT}"

python3 - "${JSON_REPORT}" "${RUN_LOG}" "${SUMMARY_PATH}" "${MARKDOWN_REPORT}" <<'PY'
import json
import sys
from pathlib import Path

report_path = Path(sys.argv[1])
log_path = Path(sys.argv[2])
summary_path = Path(sys.argv[3])
markdown_path = Path(sys.argv[4])

report = json.loads(report_path.read_text(encoding="utf-8"))
summary = report["summary"]
log_lines = [
    " ".join(
        [
            f"bundle_id={report['bundle_id']}",
            f"verdict={summary['certification_verdict']}",
            f"green={summary['accepted_rows']}",
            f"red={summary['rejected_rows']}",
            f"parent_close_allowed={str(summary['parent_epic_close_allowed']).lower()}",
        ]
    )
]
for row in report["rows"]:
    log_lines.append(
        " ".join(
            [
                f"child={row['child_bead_id']}",
                f"classification={row['classification']}",
                f"accepted={str(row['accepted']).lower()}",
                f"executed_tests={row['executed_tests']}",
                f"artifact={row['artifact_path']}",
            ]
        )
    )
for row in report["rejected_rows"]:
    log_lines.append(
        " ".join(
            [
                f"fixture={row['evidence_id']}",
                "classification=red",
                f"reasons={','.join(row['reason_codes'])}",
            ]
        )
    )
log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")

summary_path.write_text(
    json.dumps(
        {
            "schema_version": "second-wave-swarm-control-loop-certification-e2e-summary-v1",
            "run_id": report_path.parent.name.removeprefix("run_"),
            "dry_run_only": True,
            "non_mutating": True,
            "runs_proof_commands": False,
            "json_report": str(report_path),
            "markdown_report": str(markdown_path),
            "log_path": str(log_path),
            "certification_verdict": summary["certification_verdict"],
            "operator_workflow_certified": summary["operator_workflow_certified"],
            "parent_epic_close_allowed": summary["parent_epic_close_allowed"],
            "accepted_rows": summary["accepted_rows"],
            "rejected_rows": summary["rejected_rows"],
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY

echo "${SUMMARY_PATH}"
