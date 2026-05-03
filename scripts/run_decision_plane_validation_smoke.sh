#!/usr/bin/env bash
set -euo pipefail

# Schema anchors for contract invariants:
# - decision-plane-validation-smoke-bundle-v1
# - decision-plane-validation-smoke-run-report-v1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONTRACT_ARTIFACT="${PROJECT_ROOT}/artifacts/decision_plane_validation_v1.json"
OUTPUT_ROOT="${DECISION_PLANE_SMOKE_OUTPUT_DIR:-${PROJECT_ROOT}/target/decision-plane-validation-smoke}"
ARTIFACT_MIRROR_ROOT="${DECISION_PLANE_SMOKE_ARTIFACT_ROOT:-${PROJECT_ROOT}/.decision-plane-validation-smoke-artifacts}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
LIST_ONLY=0
DRY_RUN=1

declare -a SELECTED_SCENARIOS=()

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_decision_plane_validation_smoke.sh [options]

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
        echo "FATAL: jq is required for decision plane validation smoke runner" >&2
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

controller_snapshot_ledger_schema_version() {
    jq -r '.controller_snapshot_ledger.schema_version' "$CONTRACT_ARTIFACT"
}

controller_snapshot_ledger_top_level_fields_json() {
    jq -c '.controller_snapshot_ledger.top_level_fields' "$CONTRACT_ARTIFACT"
}

controller_snapshot_ledger_controller_fields_json() {
    jq -c '.controller_snapshot_ledger.controller_fields' "$CONTRACT_ARTIFACT"
}

controller_snapshot_ledger_planner_render_order_json() {
    jq -c '.controller_snapshot_ledger.planner_render_order' "$CONTRACT_ARTIFACT"
}

list_scenarios() {
    jq -r '.smoke_scenarios[] | [.scenario_id, .description] | @tsv' "$CONTRACT_ARTIFACT" \
        | while IFS=$'\t' read -r sid desc; do
            printf '%-38s %s\n' "$sid" "$desc"
        done
}

load_scenario_json() {
    local sid="$1"
    jq -c --arg sid "$sid" '.smoke_scenarios[] | select(.scenario_id == $sid)' "$CONTRACT_ARTIFACT"
}

append_result() {
    local entry="$1"
    if [[ -z "${RESULTS_JSON:-}" ]]; then
        RESULTS_JSON="$entry"
    else
        RESULTS_JSON="${RESULTS_JSON},${entry}"
    fi
}

manifest_path_value() {
    local path="$1"
    if [[ "$path" == "${PROJECT_ROOT}/"* ]]; then
        printf '%s\n' "${path#${PROJECT_ROOT}/}"
    else
        printf '%s\n' "$path"
    fi
}

extract_log_json_artifact() {
    local prefix="$1"
    local log_file="$2"
    local output_file="$3"
    local line payload
    line="$(grep -F "$prefix" "$log_file" | tail -n1 || true)"
    if [[ -z "$line" ]]; then
        return 1
    fi
    payload="${line#"$prefix"}"
    printf '%s\n' "$payload" | jq '.' > "$output_file"
}

run_scenario() {
    local sid="$1"
    local scenario_json
    scenario_json="$(load_scenario_json "$sid")"
    if [[ -z "$scenario_json" ]]; then
        echo "FATAL: unknown scenario id: ${sid}" >&2
        return 1
    fi

    local description command expected_artifacts
    description="$(jq -r '.description' <<<"$scenario_json")"
    command="$(jq -r '.command' <<<"$scenario_json")"
    expected_artifacts="$(jq -c '.expected_artifacts // []' <<<"$scenario_json")"

    local scenario_dir="${RUN_DIR}/${sid}"
    local log_file="${scenario_dir}/run.log"
    local summary_file="${scenario_dir}/bundle_manifest.json"
    local artifact_mirror_dir="${ARTIFACT_MIRROR_ROOT}/run_${TIMESTAMP}/${sid}"
    local controller_ledger_artifact="${artifact_mirror_dir}/controller_snapshot_ledger.json"
    local planner_rows_artifact="${artifact_mirror_dir}/controller_snapshot_planner_rows.json"
    local command_for_execution="$command"
    local started_ts ended_ts status rc

    mkdir -p "$scenario_dir" "$artifact_mirror_dir"
    started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    echo ">>> Running scenario ${sid}"
    echo "    description: ${description}"
    echo "    command: ${command}"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf 'DRY_RUN scenario=%s\n' "$sid" | tee "$log_file" >/dev/null
        rc=0
        status="dry_run"
    else
        if [[ "$sid" == "AA023-SMOKE-CONTROLLER-LEDGER" ]]; then
            command_for_execution="${command/rch exec -- env /rch exec -- env ASUPERSYNC_CONTROLLER_LEDGER_STDOUT=1 ASUPERSYNC_CONTROLLER_LEDGER_PLANNER_ROWS_STDOUT=1 }"
        fi
        rc=0
        eval "$command_for_execution" > "$log_file" 2>&1 || rc=$?
        if [[ "$rc" -eq 0 ]]; then
            if [[ "$sid" == "AA023-SMOKE-CONTROLLER-LEDGER" ]]; then
                if ! extract_log_json_artifact "ASUPERSYNC_CONTROLLER_LEDGER_JSON=" "$log_file" "$controller_ledger_artifact"; then
                    echo "FATAL: controller ledger artifact marker missing from run log" >> "$log_file"
                    rc=1
                fi
                if ! extract_log_json_artifact "ASUPERSYNC_CONTROLLER_LEDGER_PLANNER_ROWS_JSON=" "$log_file" "$planner_rows_artifact"; then
                    echo "FATAL: planner rows artifact marker missing from run log" >> "$log_file"
                    rc=1
                fi
            fi
            if [[ "$rc" -eq 0 ]]; then
                status="passed"
            else
                status="failed"
            fi
        else
            status="failed"
        fi
    fi

    ended_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    cat >"$summary_file" <<JSON
{
  "schema_version": "$(json_escape "$(bundle_schema_version)")",
  "contract_version": "$(json_escape "$(contract_version)")",
  "controller_snapshot_ledger_schema_version": "$(json_escape "$(controller_snapshot_ledger_schema_version)")",
  "controller_snapshot_ledger_top_level_fields": $(controller_snapshot_ledger_top_level_fields_json),
  "controller_snapshot_ledger_controller_fields": $(controller_snapshot_ledger_controller_fields_json),
  "controller_snapshot_ledger_planner_render_order": $(controller_snapshot_ledger_planner_render_order_json),
  "scenario_id": "$(json_escape "$sid")",
  "description": "$(json_escape "$description")",
  "command": "$(json_escape "$command")",
  "expected_artifacts": ${expected_artifacts},
  "controller_snapshot_ledger_artifact_path": $( [[ -f "$controller_ledger_artifact" ]] && printf '"%s"' "$(json_escape "$(manifest_path_value "$controller_ledger_artifact")")" || printf 'null' ),
  "controller_snapshot_planner_rows_artifact_path": $( [[ -f "$planner_rows_artifact" ]] && printf '"%s"' "$(json_escape "$(manifest_path_value "$planner_rows_artifact")")" || printf 'null' ),
  "artifact_path": "$(json_escape "$summary_file")",
  "run_log_path": "$(json_escape "$log_file")",
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

for sid in "${SELECTED_SCENARIOS[@]}"; do
    if ! run_scenario "$sid"; then
        OVERALL_RC=1
    fi
done

RUN_REPORT="${RUN_DIR}/run_report.json"
cat >"$RUN_REPORT" <<JSON
{
  "schema_version": "$(json_escape "$(report_schema_version)")",
  "contract_version": "$(json_escape "$(contract_version)")",
  "controller_snapshot_ledger_schema_version": "$(json_escape "$(controller_snapshot_ledger_schema_version)")",
  "controller_snapshot_ledger_top_level_fields": $(controller_snapshot_ledger_top_level_fields_json),
  "controller_snapshot_ledger_controller_fields": $(controller_snapshot_ledger_controller_fields_json),
  "controller_snapshot_ledger_planner_render_order": $(controller_snapshot_ledger_planner_render_order_json),
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
echo "         DECISION PLANE VALIDATION SMOKE SUMMARY                   "
echo "==================================================================="
echo "  Run dir:   ${RUN_DIR}"
echo "  Report:    ${RUN_REPORT}"
echo "  Mode:      $([ "$DRY_RUN" -eq 1 ] && printf "DRY-RUN" || printf "EXECUTE")"
echo "  Status:    $([ "$OVERALL_RC" -eq 0 ] && printf "PASSED" || printf "FAILED")"
echo "==================================================================="

exit "$OVERALL_RC"
