#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONTRACT_ARTIFACT="${PROJECT_ROOT}/artifacts/generated_smoke_artifact_inventory_v1.json"
OUTPUT_ROOT="${GENERATED_SMOKE_ARTIFACT_INVENTORY_OUTPUT_DIR:-${PROJECT_ROOT}/target/generated-smoke-artifact-inventory-smoke}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
LIST_ONLY=0
DRY_RUN=1
SELECTED_SCENARIO=""

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_generated_smoke_artifact_inventory_smoke.sh [options]

Options:
  --list                    List scenario IDs and exit
  --scenario <id>           Run one scenario
  --output-root <dir>       Override output root
  --dry-run                 Emit manifests without strict host validation (default)
  --execute                 Validate current host generated clusters against inventory
  -h, --help                Show help
USAGE
}

require_tools() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required for generated smoke artifact inventory validation" >&2
        exit 1
    fi
    if ! command -v sha256sum >/dev/null 2>&1; then
        echo "FATAL: sha256sum is required for generated smoke artifact inventory validation" >&2
        exit 1
    fi
    if [ ! -f "$CONTRACT_ARTIFACT" ]; then
        echo "FATAL: inventory artifact missing at ${CONTRACT_ARTIFACT}" >&2
        exit 1
    fi
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

contract_version() {
    jq -r '.schema_version' "$CONTRACT_ARTIFACT"
}

list_scenarios() {
    jq -r '.smoke_scenarios[] | [.scenario_id, .description] | @tsv' "$CONTRACT_ARTIFACT" \
        | while IFS=$'\t' read -r scenario_id description; do
            printf '%-56s %s\n' "$scenario_id" "$description"
        done
}

count_field() {
    local expression="$1"
    jq -r "$expression" "$CONTRACT_ARTIFACT"
}

expected_count() {
    local key="$1"
    jq -r --arg scenario_id "$SELECTED_SCENARIO" --arg key "$key" \
        '.smoke_scenarios[] | select(.scenario_id == $scenario_id) | .expected_counts[$key]' \
        "$CONTRACT_ARTIFACT"
}

cluster_files() {
    local root="$1"
    find "$PROJECT_ROOT/$root" -maxdepth 3 -type f | sort | sed "s#^${PROJECT_ROOT}/##"
}

cluster_file_count() {
    local root="$1"
    if [ ! -d "$PROJECT_ROOT/$root" ]; then
        printf '0'
        return
    fi
    cluster_files "$root" | sed '/^$/d' | wc -l | tr -d ' '
}

cluster_total_bytes() {
    local root="$1"
    if [ ! -d "$PROJECT_ROOT/$root" ]; then
        printf '0'
        return
    fi
    cluster_files "$root" | xargs -r -I{} wc -c "$PROJECT_ROOT/{}" | awk '{sum += $1} END {print sum + 0}'
}

cluster_list_hash() {
    local root="$1"
    if [ ! -d "$PROJECT_ROOT/$root" ]; then
        printf 'missing'
        return
    fi
    cluster_files "$root" | sha256sum | awk '{print $1}'
}

cluster_checksum_hash() {
    local root="$1"
    if [ ! -d "$PROJECT_ROOT/$root" ]; then
        printf 'missing'
        return
    fi
    cluster_files "$root" | xargs -r -I{} sha256sum "$PROJECT_ROOT/{}" | sed "s#${PROJECT_ROOT}/##" | sha256sum | awk '{print $1}'
}

write_cluster_report() {
    local report_path="$1"
    local first=1
    printf '[' >"$report_path"
    while IFS=$'\t' read -r cluster_id root expected_files expected_bytes expected_list_hash expected_checksum_hash signoff_status owner_count owner_beads_json runner_path scenario_ids_json reproduction_command cluster_retention_decision no_deletion_confirmation; do
        local present actual_files actual_bytes actual_list_hash actual_checksum_hash checksum_match
        present=false
        if [ -d "$PROJECT_ROOT/$root" ]; then
            present=true
        fi
        actual_files="$(cluster_file_count "$root")"
        actual_bytes="$(cluster_total_bytes "$root")"
        actual_list_hash="$(cluster_list_hash "$root")"
        actual_checksum_hash="$(cluster_checksum_hash "$root")"
        checksum_match=false
        if [[ "$actual_files" == "$expected_files" ]] \
            && [[ "$actual_bytes" == "$expected_bytes" ]] \
            && [[ "$actual_list_hash" == "$expected_list_hash" ]] \
            && [[ "$actual_checksum_hash" == "$expected_checksum_hash" ]]; then
            checksum_match=true
        fi

        if [[ "$first" -eq 0 ]]; then
            printf ',\n' >>"$report_path"
        fi
        first=0
        cat >>"$report_path" <<JSON
  {
    "cluster_id": "$(json_escape "$cluster_id")",
    "output_root": "$(json_escape "$root")",
    "owner_beads": ${owner_beads_json},
    "present": ${present},
    "owner_bead_count": ${owner_count},
    "runner_path": "$(json_escape "$runner_path")",
    "scenario_ids": ${scenario_ids_json},
    "reproduction_command": "$(json_escape "$reproduction_command")",
    "retention_decision": "$(json_escape "$cluster_retention_decision")",
    "no_deletion_confirmation": ${no_deletion_confirmation},
    "expected_file_count": ${expected_files},
    "actual_file_count": ${actual_files},
    "expected_total_bytes": ${expected_bytes},
    "actual_total_bytes": ${actual_bytes},
    "expected_stable_file_list_sha256": "$(json_escape "$expected_list_hash")",
    "actual_stable_file_list_sha256": "$(json_escape "$actual_list_hash")",
    "expected_checksum_manifest_sha256": "$(json_escape "$expected_checksum_hash")",
    "actual_checksum_manifest_sha256": "$(json_escape "$actual_checksum_hash")",
    "checksum_match": ${checksum_match},
    "signoff_status": "$(json_escape "$signoff_status")"
  }
JSON
    done < <(jq -r '.clusters[] | [
        .cluster_id,
        .output_root,
        .expected_file_count,
        .expected_total_bytes,
        .stable_file_list_sha256,
        .checksum_manifest_sha256,
        .signoff_status,
        (.owner_beads | length),
        (.owner_beads | @json),
        .runner_path,
        (.scenario_ids | @json),
        .reproduction_command,
        .retention_decision,
        (.no_deletion_confirmation | tostring)
    ] | @tsv' "$CONTRACT_ARTIFACT")
    printf '\n]\n' >>"$report_path"
}

run_scenario() {
    local scenario_id="$1"
    local scenario_json scenario_dir log_file cluster_report run_report bundle_manifest
    scenario_json="$(jq -c --arg scenario_id "$scenario_id" '.smoke_scenarios[] | select(.scenario_id == $scenario_id)' "$CONTRACT_ARTIFACT")"
    if [[ -z "$scenario_json" ]]; then
        echo "FATAL: unknown scenario id: ${scenario_id}" >&2
        return 1
    fi

    local started_ts ended_ts mode status validation_passed script_exit_code
    local source_repo_hash git_branch git_upstream retention_decision fallback_decision no_deletion_policy rch_queue_state
    local cluster_count present_cluster_count missing_cluster_count file_count total_bytes checksum_match_count owner_bead_count fail_closed_cluster_count no_deletion_count

    scenario_dir="${RUN_DIR}/${scenario_id}"
    log_file="${scenario_dir}/run.log"
    cluster_report="${scenario_dir}/cluster_report.json"
    bundle_manifest="${scenario_dir}/bundle_manifest.json"
    run_report="${scenario_dir}/run_report.json"
    mkdir -p "$scenario_dir"

    started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    mode="$([ "$DRY_RUN" -eq 1 ] && printf dry_run || printf execute)"
    source_repo_hash="$(git -C "$PROJECT_ROOT" rev-parse --short=12 HEAD 2>/dev/null || printf unknown)"
    git_branch="$(git -C "$PROJECT_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || printf unknown)"
    git_upstream="$(git -C "$PROJECT_ROOT" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || printf none)"
    retention_decision="$(jq -r '.policy.retention_decision' "$CONTRACT_ARTIFACT")"
    fallback_decision="$(jq -r '.policy.fallback_decision' "$CONTRACT_ARTIFACT")"
    no_deletion_policy="$(jq -r '.policy.no_deletion_confirmation' "$CONTRACT_ARTIFACT")"
    rch_queue_state="not_applicable_no_cargo_invoked"
    write_cluster_report "$cluster_report"

    cluster_count="$(jq length "$cluster_report")"
    present_cluster_count="$(jq '[.[] | select(.present == true)] | length' "$cluster_report")"
    missing_cluster_count="$(jq '[.[] | select(.present == false)] | length' "$cluster_report")"
    file_count="$(jq '[.[].actual_file_count] | add // 0' "$cluster_report")"
    total_bytes="$(jq '[.[].actual_total_bytes] | add // 0' "$cluster_report")"
    checksum_match_count="$(jq '[.[] | select(.checksum_match == true)] | length' "$cluster_report")"
    owner_bead_count="$(jq '[.clusters[].owner_beads[]] | unique | length' "$CONTRACT_ARTIFACT")"
    fail_closed_cluster_count="$(jq '[.clusters[] | select(.signoff_status | startswith("fail_closed"))] | length' "$CONTRACT_ARTIFACT")"
    no_deletion_count="$(jq '[.clusters[] | select(.no_deletion_confirmation == true)] | length' "$CONTRACT_ARTIFACT")"

    validation_passed=false
    script_exit_code=0
    status="dry_run"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        status="passed"
        if [[ "$cluster_count" -ne "$(expected_count cluster_count)" ]]; then
            status="failed"
        fi
        if [[ "$file_count" -ne "$(expected_count file_count)" ]]; then
            status="failed"
        fi
        if [[ "$total_bytes" -ne "$(expected_count total_bytes)" ]]; then
            status="failed"
        fi
        if [[ "$checksum_match_count" -ne "$cluster_count" ]]; then
            status="failed"
        fi
        if [[ "$fail_closed_cluster_count" -ne "$(expected_count fail_closed_cluster_count)" ]]; then
            status="failed"
        fi
        if [[ "$no_deletion_count" -ne "$(expected_count no_deletion_confirmation_count)" ]]; then
            status="failed"
        fi
        if [[ "$status" == "passed" ]]; then
            validation_passed=true
        else
            script_exit_code=1
        fi
    fi

    {
        echo "scenario_id=${scenario_id}"
        echo "contract_version=$(contract_version)"
        echo "source_repo_hash=${source_repo_hash}"
        echo "git_branch=${git_branch}"
        echo "git_upstream=${git_upstream}"
        echo "output_root=${OUTPUT_ROOT}"
        echo "run_dir=${RUN_DIR}"
        echo "inventory_artifact_path=${CONTRACT_ARTIFACT}"
        echo "mode=${mode}"
        echo "cluster_count=${cluster_count}"
        echo "present_cluster_count=${present_cluster_count}"
        echo "missing_cluster_count=${missing_cluster_count}"
        echo "file_count=${file_count}"
        echo "total_bytes=${total_bytes}"
        echo "checksum_match_count=${checksum_match_count}"
        echo "owner_bead_count=${owner_bead_count}"
        echo "fail_closed_cluster_count=${fail_closed_cluster_count}"
        echo "no_deletion_confirmation_count=${no_deletion_count}"
        echo "retention_decision=${retention_decision}"
        echo "fallback_decision=${fallback_decision}"
        echo "no_deletion_policy=${no_deletion_policy}"
        echo "rch_queue_state=${rch_queue_state}"
        echo "cluster_report_path=${cluster_report}"
        echo "bundle_manifest_path=${bundle_manifest}"
        echo "run_report_path=${run_report}"
        echo "run_log_path=${log_file}"
        echo "final_verdict=${status}"
    } | tee "$log_file" >/dev/null

    ended_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    cat >"$bundle_manifest" <<JSON
{
  "schema_version": "generated-smoke-artifact-inventory-bundle-v1",
  "contract_version": "$(json_escape "$(contract_version)")",
  "scenario_id": "$(json_escape "$scenario_id")",
  "mode": "$(json_escape "$mode")",
  "source_repo_hash": "$(json_escape "$source_repo_hash")",
  "git_branch": "$(json_escape "$git_branch")",
  "git_upstream": "$(json_escape "$git_upstream")",
  "output_root": "$(json_escape "$OUTPUT_ROOT")",
  "run_dir": "$(json_escape "$RUN_DIR")",
  "inventory_artifact_path": "$(json_escape "$CONTRACT_ARTIFACT")",
  "cluster_report_path": "$(json_escape "$cluster_report")",
  "run_log_path": "$(json_escape "$log_file")",
  "retention_decision": "$(json_escape "$retention_decision")",
  "fallback_decision": "$(json_escape "$fallback_decision")",
  "no_deletion_policy": ${no_deletion_policy},
  "rch_queue_state": "$(json_escape "$rch_queue_state")",
  "cluster_count": ${cluster_count},
  "present_cluster_count": ${present_cluster_count},
  "missing_cluster_count": ${missing_cluster_count},
  "file_count": ${file_count},
  "total_bytes": ${total_bytes},
  "checksum_match_count": ${checksum_match_count},
  "owner_bead_count": ${owner_bead_count},
  "fail_closed_cluster_count": ${fail_closed_cluster_count},
  "no_deletion_confirmation_count": ${no_deletion_count},
  "validation_passed": ${validation_passed},
  "status": "$(json_escape "$status")",
  "started_ts": "$(json_escape "$started_ts")",
  "ended_ts": "$(json_escape "$ended_ts")"
}
JSON

    cat >"$run_report" <<JSON
{
  "schema_version": "generated-smoke-artifact-inventory-run-report-v1",
  "contract_version": "$(json_escape "$(contract_version)")",
  "scenario_id": "$(json_escape "$scenario_id")",
  "mode": "$(json_escape "$mode")",
  "script_exit_code": ${script_exit_code},
  "validation_passed": ${validation_passed},
  "status": "$(json_escape "$status")",
  "message": "$([ "$status" == "passed" ] && printf "generated smoke artifact clusters are owned, checksum-stable, and ignored as local evidence" || printf "generated smoke artifact inventory was not executed or failed validation")",
  "generated_artifact_paths": [
    "$(json_escape "$cluster_report")",
    "$(json_escape "$bundle_manifest")",
    "$(json_escape "$run_report")",
    "$(json_escape "$log_file")"
  ],
  "source_repo_hash": "$(json_escape "$source_repo_hash")",
  "git_branch": "$(json_escape "$git_branch")",
  "git_upstream": "$(json_escape "$git_upstream")",
  "output_root": "$(json_escape "$OUTPUT_ROOT")",
  "run_dir": "$(json_escape "$RUN_DIR")",
  "inventory_artifact_path": "$(json_escape "$CONTRACT_ARTIFACT")",
  "cluster_report_path": "$(json_escape "$cluster_report")",
  "bundle_manifest_path": "$(json_escape "$bundle_manifest")",
  "run_log_path": "$(json_escape "$log_file")",
  "retention_decision": "$(json_escape "$retention_decision")",
  "fallback_decision": "$(json_escape "$fallback_decision")",
  "no_deletion_policy": ${no_deletion_policy},
  "rch_queue_state": "$(json_escape "$rch_queue_state")",
  "cluster_count": ${cluster_count},
  "present_cluster_count": ${present_cluster_count},
  "missing_cluster_count": ${missing_cluster_count},
  "file_count": ${file_count},
  "total_bytes": ${total_bytes},
  "checksum_match_count": ${checksum_match_count},
  "owner_bead_count": ${owner_bead_count},
  "fail_closed_cluster_count": ${fail_closed_cluster_count},
  "no_deletion_confirmation_count": ${no_deletion_count},
  "final_verdict": "$(json_escape "$status")"
}
JSON

    echo ""
    echo "==================================================================="
    echo "        GENERATED SMOKE ARTIFACT INVENTORY SUMMARY                "
    echo "==================================================================="
    echo "  Run dir:   ${RUN_DIR}"
    echo "  Report:    ${run_report}"
    echo "  Mode:      $(printf '%s' "$mode" | tr '[:lower:]' '[:upper:]')"
    echo "  Status:    $(printf '%s' "$status" | tr '[:lower:]' '[:upper:]')"
    echo "==================================================================="

    [[ "$status" != "failed" ]]
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            LIST_ONLY=1
            shift
            ;;
        --scenario)
            SELECTED_SCENARIO="${2:-}"
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

if [[ -z "$SELECTED_SCENARIO" ]]; then
    SELECTED_SCENARIO="$(jq -r '.smoke_scenarios[0].scenario_id' "$CONTRACT_ARTIFACT")"
fi

mkdir -p "$RUN_DIR"
run_scenario "$SELECTED_SCENARIO"
