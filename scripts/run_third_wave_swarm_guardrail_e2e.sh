#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FIXTURE="${THIRD_WAVE_GUARDRAIL_FIXTURE:-${REPO_ROOT}/artifacts/third_wave_swarm_guardrail_e2e_contract_v1.json}"
OUTPUT_ROOT="${THIRD_WAVE_GUARDRAIL_OUTPUT_ROOT:-${REPO_ROOT}/target/third-wave-swarm-guardrail-e2e}"
RUN_ID="local-check"
GENERATED_AT="2026-06-06T17:20:00Z"

usage() {
    cat <<'USAGE'
Usage: scripts/run_third_wave_swarm_guardrail_e2e.sh [options]

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
JSON_REPORT="${REPORT_DIR}/guardrail-e2e.json"
MARKDOWN_REPORT="${REPORT_DIR}/guardrail-e2e.md"
RUN_LOG="${REPORT_DIR}/guardrail-e2e.log"
SUMMARY_PATH="${REPORT_DIR}/summary.json"

mkdir -p "${REPORT_DIR}"

python3 "${REPO_ROOT}/scripts/third_wave_swarm_guardrail_e2e.py" \
    --fixture "${FIXTURE}" \
    --repo-root "${REPO_ROOT}" \
    --generated-at "${GENERATED_AT}" \
    --output json > "${JSON_REPORT}"

python3 "${REPO_ROOT}/scripts/third_wave_swarm_guardrail_e2e.py" \
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
            f"verdict={summary['guardrail_verdict']}",
            f"components={summary['component_count']}",
            f"passed={summary['passed_components']}",
            f"failed={summary['failed_components']}",
            f"child_scenarios={summary['child_scenario_count']}",
        ]
    )
]
for component in report["components"]:
    log_lines.append(
        " ".join(
            [
                f"component={component['id']}",
                f"status={component['status']}",
                f"child_rows={component['child_row_count']}",
                f"classifications={component['required_classification_count']}",
                f"markers={component['required_marker_count']}",
            ]
        )
    )
log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")

summary_path.write_text(
    json.dumps(
        {
            "schema_version": "third-wave-swarm-guardrail-e2e-summary-v1",
            "run_id": report_path.parent.name.removeprefix("run_"),
            "dry_run_only": summary["dry_run_only"],
            "non_mutating": summary["non_mutating"],
            "invokes_child_helpers": summary["invokes_child_helpers"],
            "uses_live_external_services": summary["uses_live_external_services"],
            "runs_proof_commands": summary["runs_proof_commands"],
            "json_report": str(report_path),
            "markdown_report": str(markdown_path),
            "log_path": str(log_path),
            "guardrail_verdict": summary["guardrail_verdict"],
            "component_count": summary["component_count"],
            "passed_components": summary["passed_components"],
            "failed_components": summary["failed_components"],
            "child_scenario_count": summary["child_scenario_count"],
            "required_classification_count": summary["required_classification_count"],
            "required_marker_count": summary["required_marker_count"],
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY

echo "${SUMMARY_PATH}"
