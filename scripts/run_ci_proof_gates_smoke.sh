#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONTRACT_ARTIFACT="${PROJECT_ROOT}/artifacts/ci_proof_gates_v1.json"
OUTPUT_ROOT="${CPG_SMOKE_OUTPUT_DIR:-${PROJECT_ROOT}/target/ci-proof-gates-smoke}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
LIST_ONLY=0
DRY_RUN=1

declare -a SELECTED_SCENARIOS=()

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_ci_proof_gates_smoke.sh [options]

Options:
  --list                    List scenario IDs and exit
  --scenario <id>           Run one scenario (repeatable)
  --output-root <dir>       Override output root
  --dry-run                 Emit manifests without executing (default)
  --execute                 Execute cargo test scenarios
  -h, --help                Show help
USAGE
}

require_tools() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required" >&2; exit 1
    fi
    if [ ! -f "$CONTRACT_ARTIFACT" ]; then
        echo "FATAL: contract artifact missing at ${CONTRACT_ARTIFACT}" >&2; exit 1
    fi
}

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
contract_version() { jq -r '.contract_version' "$CONTRACT_ARTIFACT"; }
bundle_schema_version() { jq -r '.runner_bundle_schema_version' "$CONTRACT_ARTIFACT"; }
report_schema_version() { jq -r '.runner_report_schema_version' "$CONTRACT_ARTIFACT"; }

list_scenarios() {
    jq -r '.smoke_scenarios[] | [.scenario_id, .description] | @tsv' "$CONTRACT_ARTIFACT" \
        | while IFS=$'\t' read -r sid desc; do printf '%-38s %s\n' "$sid" "$desc"; done
}

load_scenario_json() {
    jq -c --arg sid "$1" '.smoke_scenarios[] | select(.scenario_id == $sid)' "$CONTRACT_ARTIFACT"
}

RESULTS_JSON=""
append_result() {
    if [[ -z "$RESULTS_JSON" ]]; then RESULTS_JSON="$1"; else RESULTS_JSON="${RESULTS_JSON},$1"; fi
}

run_scenario() {
    local sid="$1" scenario_json description command scenario_dir log_file summary_file started_ts ended_ts status rc
    scenario_json="$(load_scenario_json "$sid")"
    [[ -z "$scenario_json" ]] && { echo "FATAL: unknown scenario: $sid" >&2; return 1; }
    description="$(jq -r '.description' <<<"$scenario_json")"
    command="$(jq -r '.command' <<<"$scenario_json")"
    scenario_dir="${RUN_DIR}/${sid}"; log_file="${scenario_dir}/run.log"; summary_file="${scenario_dir}/bundle_manifest.json"
    mkdir -p "$scenario_dir"
    started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ">>> Running scenario ${sid}"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf 'DRY_RUN scenario=%s\n' "$sid" >"$log_file"; rc=0; status="dry_run"
    else
        rc=0; eval "$command" >"$log_file" 2>&1 || rc=$?
        status="$( [[ "$rc" -eq 0 ]] && printf "passed" || printf "failed" )"
    fi
    ended_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    cat >"$summary_file" <<JSON
{
  "schema_version": "$(json_escape "$(bundle_schema_version)")",
  "contract_version": "$(json_escape "$(contract_version)")",
  "scenario_id": "$(json_escape "$sid")",
  "description": "$(json_escape "$description")",
  "status": "$(json_escape "$status")",
  "exit_code": ${rc},
  "started_ts": "$(json_escape "$started_ts")",
  "ended_ts": "$(json_escape "$ended_ts")"
}
JSON
    append_result "$(jq -c '.' "$summary_file")"
    [[ "$rc" -eq 0 ]]
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list) LIST_ONLY=1; shift ;;
        --scenario) SELECTED_SCENARIOS+=("${2:-}"); shift 2 ;;
        --output-root) OUTPUT_ROOT="${2:-}"; RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --execute) DRY_RUN=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown: $1" >&2; usage >&2; exit 1 ;;
    esac
done

require_tools
if [[ "$LIST_ONLY" -eq 1 ]]; then list_scenarios; exit 0; fi
if [[ "${#SELECTED_SCENARIOS[@]}" -eq 0 ]]; then
    mapfile -t SELECTED_SCENARIOS < <(jq -r '.smoke_scenarios[].scenario_id' "$CONTRACT_ARTIFACT")
fi

mkdir -p "$RUN_DIR"; OVERALL_RC=0
for sid in "${SELECTED_SCENARIOS[@]}"; do run_scenario "$sid" || OVERALL_RC=1; done

RUN_REPORT="${RUN_DIR}/run_report.json"
cat >"$RUN_REPORT" <<JSON
{
  "schema_version": "$(json_escape "$(report_schema_version)")",
  "contract_version": "$(json_escape "$(contract_version)")",
  "run_dir": "$(json_escape "$RUN_DIR")",
  "dry_run": $( [[ "$DRY_RUN" -eq 1 ]] && printf 'true' || printf 'false' ),
  "results": [${RESULTS_JSON}],
  "status": "$([ "$OVERALL_RC" -eq 0 ] && printf "passed" || printf "failed")"
}
JSON

echo ""
echo "==================================================================="
echo "       CI PROOF GATES SMOKE SUMMARY                                "
echo "==================================================================="
echo "  Run dir:   ${RUN_DIR}"
echo "  Mode:      $([ "$DRY_RUN" -eq 1 ] && printf "DRY-RUN" || printf "EXECUTE")"
echo "  Status:    $([ "$OVERALL_RC" -eq 0 ] && printf "PASSED" || printf "FAILED")"
echo "==================================================================="

exit "$OVERALL_RC"
