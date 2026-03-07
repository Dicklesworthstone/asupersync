#!/usr/bin/env bash
set -euo pipefail

# Schema anchors for contract invariants:
# - runtime-control-seam-smoke-bundle-v1
# - runtime-control-seam-smoke-run-report-v1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
INVENTORY_ARTIFACT="${PROJECT_ROOT}/artifacts/runtime_control_seam_inventory_v1.json"
OUTPUT_ROOT="${CONTROL_SEAM_SMOKE_OUTPUT_DIR:-${PROJECT_ROOT}/target/control-seam-smoke}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
LIST_ONLY=0
DRY_RUN=1

declare -a SELECTED_SEAMS=()

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_runtime_control_seam_smoke.sh [options]

Options:
  --list                  List seam IDs and exit
  --seam <id>             Run one seam (repeatable)
  --output-root <dir>     Override output root (default: target/control-seam-smoke)
  --dry-run               Emit manifests without executing commands (default)
  --execute               Execute comparator smoke commands
  -h, --help              Show help
USAGE
}

require_tools() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required for control-seam smoke runner" >&2
        exit 1
    fi
    if [ ! -f "$INVENTORY_ARTIFACT" ]; then
        echo "FATAL: inventory artifact missing at ${INVENTORY_ARTIFACT}" >&2
        exit 1
    fi
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

artifact_contract_version() {
    jq -r '.contract_version' "$INVENTORY_ARTIFACT"
}

bundle_schema_version() {
    jq -r '.runner_bundle_schema_version' "$INVENTORY_ARTIFACT"
}

report_schema_version() {
    jq -r '.runner_report_schema_version' "$INVENTORY_ARTIFACT"
}

load_seam_json() {
    local seam_id="$1"
    jq -c --arg seam_id "$seam_id" '.seams[] | select(.seam_id == $seam_id)' "$INVENTORY_ARTIFACT"
}

list_seams() {
    jq -r '.seams[] | [.seam_id, .seam_name, .layer, .baseline_selector] | @tsv' "$INVENTORY_ARTIFACT" \
        | while IFS=$'\t' read -r seam_id seam_name layer baseline_selector; do
            printf '%-38s layer=%-20s baseline=%s\n' "$seam_id" "$layer" "$baseline_selector"
        done
}

append_result() {
    local entry="$1"
    if [[ -z "${RESULTS_JSON:-}" ]]; then
        RESULTS_JSON="$entry"
    else
        RESULTS_JSON="${RESULTS_JSON},${entry}"
    fi
}

run_seam() {
    local seam_id="$1"
    local seam_json
    seam_json="$(load_seam_json "$seam_id")"
    if [[ -z "$seam_json" ]]; then
        echo "FATAL: unknown seam id: ${seam_id}" >&2
        return 1
    fi

    local seam_name scenario_id baseline_selector rollback_surface
    local comparator_command workload_ids expected_artifacts
    seam_name="$(jq -r '.seam_name' <<<"$seam_json")"
    scenario_id="$(jq -r '.seam_id' <<<"$seam_json")"
    baseline_selector="$(jq -r '.baseline_selector' <<<"$seam_json")"
    rollback_surface="$(jq -r '.rollback_surface' <<<"$seam_json")"
    comparator_command="$(jq -r '.comparator_smoke_command' <<<"$seam_json")"
    workload_ids="$(jq -c '.workload_ids' <<<"$seam_json")"
    expected_artifacts="$(jq -c '.expected_artifacts' <<<"$seam_json")"

    local seam_dir="${RUN_DIR}/${seam_id}"
    local log_file="${seam_dir}/run.log"
    local summary_file="${seam_dir}/bundle_manifest.json"
    local started_ts ended_ts status rc

    mkdir -p "$seam_dir"
    started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    echo ">>> Running seam ${seam_id}"
    echo "    name: ${seam_name}"
    echo "    baseline: ${baseline_selector}"
    echo "    command: ${comparator_command}"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf 'DRY_RUN %s\n' "$comparator_command" | tee "$log_file" >/dev/null
        rc=0
        status="dry_run"
    else
        set +e
        pushd "$PROJECT_ROOT" >/dev/null
        bash -lc "$comparator_command" 2>&1 | tee "$log_file"
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
  "contract_version": "$(json_escape "$(artifact_contract_version)")",
  "seam_id": "$(json_escape "$seam_id")",
  "seam_name": "$(json_escape "$seam_name")",
  "scenario_id": "$(json_escape "$scenario_id")",
  "workload_ids": ${workload_ids},
  "baseline_selector": "$(json_escape "$baseline_selector")",
  "rollback_surface": "$(json_escape "$rollback_surface")",
  "comparator_smoke_command": "$(json_escape "$comparator_command")",
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
        --seam)
            SELECTED_SEAMS+=("${2:-}")
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
    list_seams
    exit 0
fi

if [[ "${#SELECTED_SEAMS[@]}" -eq 0 ]]; then
    mapfile -t SELECTED_SEAMS < <(jq -r '.seams[].seam_id' "$INVENTORY_ARTIFACT")
fi

mkdir -p "$RUN_DIR"
RESULTS_JSON=""
OVERALL_RC=0

for seam_id in "${SELECTED_SEAMS[@]}"; do
    if ! run_seam "$seam_id"; then
        OVERALL_RC=1
    fi
done

RUN_REPORT="${RUN_DIR}/run_report.json"
cat >"$RUN_REPORT" <<JSON
{
  "schema_version": "$(json_escape "$(report_schema_version)")",
  "contract_version": "$(json_escape "$(artifact_contract_version)")",
  "artifact_path": "$(json_escape "$RUN_REPORT")",
  "run_dir": "$(json_escape "$RUN_DIR")",
  "selected_seams": $(jq -nc --argjson ids "$(printf '%s\n' "${SELECTED_SEAMS[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')" '$ids'),
  "dry_run": $( [[ "$DRY_RUN" -eq 1 ]] && printf 'true' || printf 'false' ),
  "results": [${RESULTS_JSON}],
  "status": "$([ "$OVERALL_RC" -eq 0 ] && printf "passed" || printf "failed")"
}
JSON

echo ""
echo "==================================================================="
echo "                 RUNTIME CONTROL-SEAM SMOKE SUMMARY               "
echo "==================================================================="
echo "  Run dir:   ${RUN_DIR}"
echo "  Report:    ${RUN_REPORT}"
echo "  Mode:      $([ "$DRY_RUN" -eq 1 ] && printf "DRY-RUN" || printf "EXECUTE")"
echo "  Status:    $([ "$OVERALL_RC" -eq 0 ] && printf "PASSED" || printf "FAILED")"
echo "==================================================================="

exit "$OVERALL_RC"
