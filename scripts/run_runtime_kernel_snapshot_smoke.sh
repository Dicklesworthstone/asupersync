#!/usr/bin/env bash
set -euo pipefail

# Schema anchors for contract invariants:
# - runtime-kernel-snapshot-smoke-bundle-v1
# - runtime-kernel-snapshot-smoke-run-report-v1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONTRACT_ARTIFACT="${PROJECT_ROOT}/artifacts/runtime_kernel_snapshot_contract_v1.json"
OUTPUT_ROOT="${RUNTIME_KERNEL_SNAPSHOT_SMOKE_OUTPUT_DIR:-${PROJECT_ROOT}/target/runtime-kernel-snapshot-smoke}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
LIST_ONLY=0
DRY_RUN=1

declare -a SELECTED_SCENARIOS=()

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_runtime_kernel_snapshot_smoke.sh [options]

Options:
  --list                    List scenario IDs and exit
  --scenario <id>           Run one scenario (repeatable)
  --output-root <dir>       Override output root (default: target/runtime-kernel-snapshot-smoke)
  --dry-run                 Emit manifests without executing commands (default)
  --execute                 Execute smoke commands
  -h, --help                Show help
USAGE
}

require_tools() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required for runtime-kernel snapshot smoke runner" >&2
        exit 1
    fi
    if [ ! -f "$CONTRACT_ARTIFACT" ]; then
        echo "FATAL: contract artifact missing at ${CONTRACT_ARTIFACT}" >&2
        exit 1
    fi
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

contract_version() {
    jq -r '.contract_version' "$CONTRACT_ARTIFACT"
}

bundle_schema_version() {
    jq -r '.runner_bundle_schema_version' "$CONTRACT_ARTIFACT"
}

report_schema_version() {
    jq -r '.runner_report_schema_version' "$CONTRACT_ARTIFACT"
}

list_scenarios() {
    jq -r '.smoke_scenarios[] | [.scenario_id, .intent] | @tsv' "$CONTRACT_ARTIFACT" \
        | while IFS=$'\t' read -r scenario_id intent; do
            printf '%-42s %s\n' "$scenario_id" "$intent"
        done
}

load_scenario_json() {
    local scenario_id="$1"
    jq -c --arg scenario_id "$scenario_id" '.smoke_scenarios[] | select(.scenario_id == $scenario_id)' "$CONTRACT_ARTIFACT"
}

append_result() {
    local entry="$1"
    if [[ -z "${RESULTS_JSON:-}" ]]; then
        RESULTS_JSON="$entry"
    else
        RESULTS_JSON="${RESULTS_JSON},${entry}"
    fi
}

run_scenario() {
    local scenario_id="$1"
    local scenario_json
    scenario_json="$(load_scenario_json "$scenario_id")"
    if [[ -z "$scenario_json" ]]; then
        echo "FATAL: unknown scenario id: ${scenario_id}" >&2
        return 1
    fi

    local intent command expected_artifacts
    intent="$(jq -r '.intent' <<<"$scenario_json")"
    command="$(jq -r '.command' <<<"$scenario_json")"
    expected_artifacts="$(jq -c '.expected_artifacts' <<<"$scenario_json")"

    local scenario_dir="${RUN_DIR}/${scenario_id}"
    local log_file="${scenario_dir}/run.log"
    local summary_file="${scenario_dir}/bundle_manifest.json"
    local started_ts ended_ts status rc

    mkdir -p "$scenario_dir"
    started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    echo ">>> Running scenario ${scenario_id}"
    echo "    intent: ${intent}"
    echo "    command: ${command}"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf 'DRY_RUN %s\n' "$command" | tee "$log_file" >/dev/null
        rc=0
        status="dry_run"
    else
        set +e
        pushd "$PROJECT_ROOT" >/dev/null
        bash -lc "$command" 2>&1 | tee "$log_file"
        rc=${PIPESTATUS[0]}
        popd >/dev/null
        set -e
        status="failed"
        if [[ "$rc" -eq 0 ]]; then
            status="passed"
        fi
    fi

    ended_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    cat >"$summary_file" <<JSON
{
  "schema_version": "$(json_escape "$(bundle_schema_version)")",
  "contract_version": "$(json_escape "$(contract_version)")",
  "scenario_id": "$(json_escape "$scenario_id")",
  "intent": "$(json_escape "$intent")",
  "smoke_command": "$(json_escape "$command")",
  "artifact_path": "$(json_escape "$summary_file")",
  "run_log_path": "$(json_escape "$log_file")",
  "status": "$(json_escape "$status")",
  "exit_code": ${rc},
  "started_ts": "$(json_escape "$started_ts")",
  "ended_ts": "$(json_escape "$ended_ts")",
  "expected_artifacts": ${expected_artifacts}
}
JSON

    append_result "$(jq -c '.' "$summary_file")"

    [[ "$rc" -eq 0 ]]
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            LIST_ONLY=1
            shift
            ;;
        --scenario)
            SELECTED_SCENARIOS+=("${2:-}")
            shift 2
            ;;
        --output-root)
            OUTPUT_ROOT="${2:-}"
            RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --execute)
            DRY_RUN=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

require_tools

if [[ "$LIST_ONLY" -eq 1 ]]; then
    list_scenarios
    exit 0
fi

if [[ "${#SELECTED_SCENARIOS[@]}" -eq 0 ]]; then
    mapfile -t SELECTED_SCENARIOS < <(jq -r '.smoke_scenarios[].scenario_id' "$CONTRACT_ARTIFACT")
fi

mkdir -p "$RUN_DIR"
RESULTS_JSON=""
OVERALL_RC=0

for scenario_id in "${SELECTED_SCENARIOS[@]}"; do
    if ! run_scenario "$scenario_id"; then
        OVERALL_RC=1
    fi
done

RUN_REPORT="${RUN_DIR}/run_report.json"
cat >"$RUN_REPORT" <<JSON
{
  "schema_version": "$(json_escape "$(report_schema_version)")",
  "contract_version": "$(json_escape "$(contract_version)")",
  "artifact_path": "$(json_escape "$RUN_REPORT")",
  "run_dir": "$(json_escape "$RUN_DIR")",
  "selected_scenarios": $(jq -nc --argjson ids "$(printf '%s\n' "${SELECTED_SCENARIOS[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')" '$ids'),
  "dry_run": $( [[ "$DRY_RUN" -eq 1 ]] && printf 'true' || printf 'false' ),
  "results": [${RESULTS_JSON}],
  "status": "$([ "$OVERALL_RC" -eq 0 ] && printf "passed" || printf "failed")"
}
JSON

echo ""
echo "==================================================================="
echo "             RUNTIME KERNEL SNAPSHOT SMOKE SUMMARY               "
echo "==================================================================="
echo "  Run dir:   ${RUN_DIR}"
echo "  Report:    ${RUN_REPORT}"
echo "  Mode:      $([ "$DRY_RUN" -eq 1 ] && printf "DRY-RUN" || printf "EXECUTE")"
echo "  Status:    $([ "$OVERALL_RC" -eq 0 ] && printf "PASSED" || printf "FAILED")"
echo "==================================================================="

exit "$OVERALL_RC"
