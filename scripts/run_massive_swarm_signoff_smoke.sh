#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
CONTRACT_ARTIFACT="${PROJECT_ROOT}/artifacts/massive_swarm_signoff_smoke_contract_v1.json"
OUTPUT_ROOT="${MASSIVE_SWARM_SIGNOFF_SMOKE_OUTPUT_DIR:-${PROJECT_ROOT}/target/massive-swarm-signoff-smoke}"
ARTIFACT_ROOT="${MASSIVE_SWARM_SIGNOFF_SMOKE_ARTIFACT_ROOT:-${PROJECT_ROOT}/.massive-swarm-signoff-smoke-artifacts}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
LIST_ONLY=0
MODE="dry-run"
SCENARIO=""

usage() {
    cat <<'EOF'
Usage: ./scripts/run_massive_swarm_signoff_smoke.sh [options]

Options:
  --list                     List available scenarios
  --scenario <id>            Run a specific scenario
  --dry-run                  Emit manifests without executing the signoff audit
  --execute                  Execute the deterministic signoff audit
  --output-root <path>       Override output root
  -h, --help                 Show this help text
EOF
}

require_tools() {
    local missing=0
    for tool in jq sha256sum date uname; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "FATAL: missing required tool: $tool" >&2
            missing=1
        fi
    done
    if [ "$missing" -ne 0 ]; then
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

required_source_skills_json() {
    jq -c '.required_source_skills' "$CONTRACT_ARTIFACT"
}

required_source_skill_phases_json() {
    jq -c '.required_source_skill_phases' "$CONTRACT_ARTIFACT"
}

required_objective_requirement_ids_json() {
    jq -c '.required_objective_requirement_ids' "$CONTRACT_ARTIFACT"
}

skill_provenance_artifact_path() {
    jq -r '.signoff_matrix[] | select(.control_id == "skill_provenance") | .artifact_path' "$CONTRACT_ARTIFACT"
}

skill_provenance_json() {
    local artifact_path
    artifact_path="$(skill_provenance_artifact_path)"
    if [ -z "$artifact_path" ] || [ ! -f "${PROJECT_ROOT}/${artifact_path}" ]; then
        echo "FATAL: skill provenance artifact missing at ${artifact_path}" >&2
        exit 1
    fi
    jq -c '.' "${PROJECT_ROOT}/${artifact_path}"
}

list_scenarios() {
    jq -r '.smoke_scenarios[] | [.scenario_id, .description] | @tsv' "$CONTRACT_ARTIFACT" \
        | while IFS=$'\t' read -r scenario_id description; do
            printf '%-52s %s\n' "$scenario_id" "$description"
        done
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --list)
                LIST_ONLY=1
                shift
                ;;
            --scenario)
                SCENARIO="${2:-}"
                if [ -z "$SCENARIO" ]; then
                    echo "FATAL: --scenario requires a value" >&2
                    exit 1
                fi
                shift 2
                ;;
            --dry-run)
                MODE="dry-run"
                shift
                ;;
            --execute)
                MODE="execute"
                shift
                ;;
            --output-root)
                OUTPUT_ROOT="${2:-}"
                if [ -z "$OUTPUT_ROOT" ]; then
                    echo "FATAL: --output-root requires a value" >&2
                    exit 1
                fi
                RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "FATAL: unknown argument: $1" >&2
                usage >&2
                exit 1
                ;;
        esac
    done
}

selected_scenario_json() {
    jq -c --arg scenario_id "$SCENARIO" '.smoke_scenarios[] | select(.scenario_id == $scenario_id)' "$CONTRACT_ARTIFACT"
}

build_child_status_json() {
    local statuses='[]'
    while IFS= read -r entry; do
        local artifact_path runner_path artifact_exists runner_exists
        artifact_path="$(jq -r '.artifact_path' <<<"$entry")"
        runner_path="$(jq -r '.runner_path' <<<"$entry")"
        artifact_exists=false
        runner_exists=false
        if [ -f "${PROJECT_ROOT}/${artifact_path}" ]; then
            artifact_exists=true
        fi
        if [ -f "${PROJECT_ROOT}/${runner_path}" ]; then
            runner_exists=true
        fi
        local merged
        merged="$(jq -cn \
            --argjson base "$entry" \
            --argjson artifact_exists "$artifact_exists" \
            --argjson runner_exists "$runner_exists" \
            '$base + {
                artifact_exists: $artifact_exists,
                runner_exists: $runner_exists
            }')"
        statuses="$(jq -cn --argjson statuses "$statuses" --argjson merged "$merged" '$statuses + [$merged]')"
    done < <(jq -c '.signoff_matrix[]' "$CONTRACT_ARTIFACT")
    printf '%s' "$statuses"
}

dirty_cluster_fail_closed_count() {
    local inventory_path
    inventory_path="$(jq -r '.signoff_matrix[] | select(.control_id == "generated_smoke_inventory") | .artifact_path' "$CONTRACT_ARTIFACT")"
    if [ -z "$inventory_path" ] || [ ! -f "${PROJECT_ROOT}/${inventory_path}" ]; then
        printf '0'
        return
    fi
    jq '[.clusters[] | select(((.signoff_status // "") | startswith("fail_closed")))] | length' "${PROJECT_ROOT}/${inventory_path}"
}

is_signoff_owned_dirty_path() {
    local path="$1"
    case "$path" in
        "artifacts/massive_swarm_signoff_smoke_contract_v1.json" \
        | "scripts/run_massive_swarm_signoff_smoke.sh" \
        | "tests/massive_swarm_signoff_contract.rs")
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

tracked_dirty_paths_json() {
    local statuses path paths='[]'
    statuses="$(git -C "$PROJECT_ROOT" status --short --untracked-files=no 2>/dev/null || true)"
    while IFS= read -r line; do
        if [ -z "$line" ]; then
            continue
        fi
        path="$(printf '%s' "$line" | cut -c4- | sed 's/^ *//')"
        if [ -z "$path" ] || is_signoff_owned_dirty_path "$path"; then
            continue
        fi
        paths="$(jq -cn --argjson paths "$paths" --arg path "$path" '$paths + [$path]')"
    done <<<"$statuses"
    printf '%s' "$paths"
}

objective_coverage_json() {
    local provenance_json
    provenance_json="$(skill_provenance_json)"
    jq -cn \
        --argjson required_source_skills "$(required_source_skills_json)" \
        --argjson required_source_skill_phases "$(required_source_skill_phases_json)" \
        --argjson required_objective_requirement_ids "$(required_objective_requirement_ids_json)" \
        --argjson source_skills "$(jq -c '.source_skills' <<<"$provenance_json")" \
        --argjson declared_objective_requirement_ids "$(jq -c '[.objective_requirements[].id]' <<<"$provenance_json")" \
        --argjson selected_bead_mappings "$(jq -c '.selected_bead_mappings' <<<"$provenance_json")" \
        --argjson source_skill_phases "$(jq -c '[.selected_bead_mappings[].source_skill_phase] | unique' <<<"$provenance_json")" \
        '{
            required_source_skills: $required_source_skills,
            actual_source_skills: $source_skills,
            missing_required_source_skills: ($required_source_skills - $source_skills),
            required_source_skill_phases: $required_source_skill_phases,
            actual_source_skill_phases: $source_skill_phases,
            missing_required_source_skill_phases: ($required_source_skill_phases - $source_skill_phases),
            required_objective_requirement_ids: $required_objective_requirement_ids,
            declared_objective_requirement_ids: $declared_objective_requirement_ids,
            missing_required_objective_requirement_ids: ($required_objective_requirement_ids - $declared_objective_requirement_ids),
            mapped_objective_requirement_ids: ([ $selected_bead_mappings[]?.objective_requirement_id ] | unique),
            unmapped_objective_requirement_ids: ($required_objective_requirement_ids - ([ $selected_bead_mappings[]?.objective_requirement_id ] | unique)),
            selected_bead_mapping_count: ($selected_bead_mappings | length),
            selected_bead_mapping_bead_ids: ([ $selected_bead_mappings[]?.bead_id ] | unique)
        }'
}

build_projection_json() {
    local scenario_json="$1"
    local child_statuses="$2"
    local objective_coverage_json="$3"
    local host_template_mode child_artifact_count trusted_child_count fail_closed_child_count
    local open_tracker_blocker_count missing_artifact_path_count missing_runner_path_count
    local dirty_fail_closed_count tracked_dirty_blocker_count no_unexplained_artifacts signoff_verdict
    local source_skill_count required_source_skill_count missing_required_source_skill_count
    local source_skill_phase_count required_source_skill_phase_count missing_required_source_skill_phase_count
    local objective_requirement_count required_objective_requirement_count
    local covered_objective_requirement_count missing_required_objective_requirement_count
    local unmapped_objective_requirement_count selected_bead_mapping_count objective_checklist_complete
    local tracked_dirty_paths_json_value

    host_template_mode="$(jq -r '.host_template_mode' <<<"$scenario_json")"
    child_artifact_count="$(jq 'length' <<<"$child_statuses")"
    trusted_child_count="$(jq '[.[] | select(.proof_status == "trusted")] | length' <<<"$child_statuses")"
    fail_closed_child_count="$(jq '[.[] | select(.proof_status == "fail_closed")] | length' <<<"$child_statuses")"
    open_tracker_blocker_count="$(jq '[.[] | select(.tracker_status != "closed")] | length' <<<"$child_statuses")"
    missing_artifact_path_count="$(jq '[.[] | select(.artifact_exists == false)] | length' <<<"$child_statuses")"
    missing_runner_path_count="$(jq '[.[] | select(.runner_exists == false)] | length' <<<"$child_statuses")"
    dirty_fail_closed_count="$(dirty_cluster_fail_closed_count)"
    tracked_dirty_paths_json_value="$(tracked_dirty_paths_json)"
    tracked_dirty_blocker_count="$(jq 'length' <<<"$tracked_dirty_paths_json_value")"
    source_skill_count="$(jq '.actual_source_skills | length' <<<"$objective_coverage_json")"
    required_source_skill_count="$(jq '.required_source_skills | length' <<<"$objective_coverage_json")"
    missing_required_source_skill_count="$(jq '.missing_required_source_skills | length' <<<"$objective_coverage_json")"
    source_skill_phase_count="$(jq '.actual_source_skill_phases | length' <<<"$objective_coverage_json")"
    required_source_skill_phase_count="$(jq '.required_source_skill_phases | length' <<<"$objective_coverage_json")"
    missing_required_source_skill_phase_count="$(jq '.missing_required_source_skill_phases | length' <<<"$objective_coverage_json")"
    objective_requirement_count="$(jq '.declared_objective_requirement_ids | length' <<<"$objective_coverage_json")"
    required_objective_requirement_count="$(jq '.required_objective_requirement_ids | length' <<<"$objective_coverage_json")"
    covered_objective_requirement_count="$(jq '.mapped_objective_requirement_ids | length' <<<"$objective_coverage_json")"
    missing_required_objective_requirement_count="$(jq '.missing_required_objective_requirement_ids | length' <<<"$objective_coverage_json")"
    unmapped_objective_requirement_count="$(jq '.unmapped_objective_requirement_ids | length' <<<"$objective_coverage_json")"
    selected_bead_mapping_count="$(jq '.selected_bead_mapping_count' <<<"$objective_coverage_json")"
    objective_checklist_complete=false
    if [ "$missing_required_source_skill_count" -eq 0 ] \
        && [ "$missing_required_source_skill_phase_count" -eq 0 ] \
        && [ "$missing_required_objective_requirement_count" -eq 0 ] \
        && [ "$unmapped_objective_requirement_count" -eq 0 ] \
        && [ "$selected_bead_mapping_count" -gt 0 ]; then
        objective_checklist_complete=true
    fi
    if [ "$dirty_fail_closed_count" -eq 0 ]; then
        no_unexplained_artifacts=true
    else
        no_unexplained_artifacts=false
    fi

    if [ "$host_template_mode" = "true" ]; then
        signoff_verdict="template_only"
    elif [ "$fail_closed_child_count" -gt 0 ] || [ "$open_tracker_blocker_count" -gt 0 ] \
        || [ "$missing_artifact_path_count" -gt 0 ] || [ "$missing_runner_path_count" -gt 0 ] \
        || [ "$dirty_fail_closed_count" -gt 0 ] || [ "$tracked_dirty_blocker_count" -gt 0 ] \
        || [ "$objective_checklist_complete" != "true" ]; then
        signoff_verdict="fail_closed"
    else
        signoff_verdict="ready_for_signoff"
    fi

    local projection_without_hash projection_hash
    projection_without_hash="$(jq -cn \
        --arg signoff_verdict "$signoff_verdict" \
        --argjson host_template_mode "$host_template_mode" \
        --argjson child_artifact_count "$child_artifact_count" \
        --argjson trusted_child_count "$trusted_child_count" \
        --argjson fail_closed_child_count "$fail_closed_child_count" \
        --argjson open_tracker_blocker_count "$open_tracker_blocker_count" \
        --argjson dirty_cluster_fail_closed_count "$dirty_fail_closed_count" \
        --argjson tracked_dirty_blocker_count "$tracked_dirty_blocker_count" \
        --argjson source_skill_count "$source_skill_count" \
        --argjson required_source_skill_count "$required_source_skill_count" \
        --argjson missing_required_source_skill_count "$missing_required_source_skill_count" \
        --argjson source_skill_phase_count "$source_skill_phase_count" \
        --argjson required_source_skill_phase_count "$required_source_skill_phase_count" \
        --argjson missing_required_source_skill_phase_count "$missing_required_source_skill_phase_count" \
        --argjson objective_requirement_count "$objective_requirement_count" \
        --argjson required_objective_requirement_count "$required_objective_requirement_count" \
        --argjson covered_objective_requirement_count "$covered_objective_requirement_count" \
        --argjson missing_required_objective_requirement_count "$missing_required_objective_requirement_count" \
        --argjson unmapped_objective_requirement_count "$unmapped_objective_requirement_count" \
        --argjson selected_bead_mapping_count "$selected_bead_mapping_count" \
        --argjson missing_artifact_path_count "$missing_artifact_path_count" \
        --argjson missing_runner_path_count "$missing_runner_path_count" \
        --argjson objective_checklist_complete "$objective_checklist_complete" \
        --argjson no_unexplained_artifacts "$no_unexplained_artifacts" \
        '{
            signoff_verdict: $signoff_verdict,
            host_template_mode: $host_template_mode,
            child_artifact_count: $child_artifact_count,
            trusted_child_count: $trusted_child_count,
            fail_closed_child_count: $fail_closed_child_count,
            open_tracker_blocker_count: $open_tracker_blocker_count,
            dirty_cluster_fail_closed_count: $dirty_cluster_fail_closed_count,
            tracked_dirty_blocker_count: $tracked_dirty_blocker_count,
            source_skill_count: $source_skill_count,
            required_source_skill_count: $required_source_skill_count,
            missing_required_source_skill_count: $missing_required_source_skill_count,
            source_skill_phase_count: $source_skill_phase_count,
            required_source_skill_phase_count: $required_source_skill_phase_count,
            missing_required_source_skill_phase_count: $missing_required_source_skill_phase_count,
            objective_requirement_count: $objective_requirement_count,
            required_objective_requirement_count: $required_objective_requirement_count,
            covered_objective_requirement_count: $covered_objective_requirement_count,
            missing_required_objective_requirement_count: $missing_required_objective_requirement_count,
            unmapped_objective_requirement_count: $unmapped_objective_requirement_count,
            selected_bead_mapping_count: $selected_bead_mapping_count,
            missing_artifact_path_count: $missing_artifact_path_count,
            missing_runner_path_count: $missing_runner_path_count,
            objective_checklist_complete: $objective_checklist_complete,
            no_unexplained_artifacts: $no_unexplained_artifacts
        }')"
    projection_hash="$(printf '%s' "$projection_without_hash" | jq -Sc . | sha256sum | awk '{print $1}')"
    jq -cn --argjson projection "$projection_without_hash" --arg projection_hash "$projection_hash" '$projection + {projection_hash: $projection_hash}'
}

run_scenario() {
    local scenario_json run_dir scenario_dir run_log_path bundle_manifest_path run_report_path scenario_report_path
    scenario_json="$(selected_scenario_json)"
    if [ -z "$scenario_json" ]; then
        echo "FATAL: unknown scenario id: ${SCENARIO}" >&2
        exit 1
    fi

    run_dir="${RUN_DIR}"
    scenario_dir="${run_dir}/${SCENARIO}"
    run_log_path="${scenario_dir}/run.log"
    bundle_manifest_path="${scenario_dir}/bundle_manifest.json"
    run_report_path="${scenario_dir}/run_report.json"
    scenario_report_path="${ARTIFACT_ROOT}/run_${TIMESTAMP}/${SCENARIO}/massive_swarm_signoff_report.json"

    mkdir -p "$scenario_dir"
    mkdir -p "$(dirname "$scenario_report_path")"

    local child_statuses projection_json expected_projection_json validation_passed status message script_exit_code
    local host_template_mode started_ts ended_ts generated_artifact_paths tracked_dirty_paths objective_coverage
    child_statuses="$(build_child_status_json)"
    objective_coverage="$(objective_coverage_json)"
    projection_json="$(build_projection_json "$scenario_json" "$child_statuses" "$objective_coverage")"
    expected_projection_json="$(jq -c '.expected_report_projection' <<<"$scenario_json")"
    host_template_mode="$(jq -r '.host_template_mode' <<<"$scenario_json")"
    tracked_dirty_paths="$(tracked_dirty_paths_json)"
    generated_artifact_paths="$(jq -cn \
        --arg bundle_manifest_path "$bundle_manifest_path" \
        --arg run_report_path "$run_report_path" \
        --arg scenario_report_path "$scenario_report_path" \
        '[ $bundle_manifest_path, $run_report_path, $scenario_report_path ]')"

    started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    status="passed"
    validation_passed=false
    script_exit_code=0
    message="signoff audit matched the contract"
    if [ "$MODE" = "dry-run" ]; then
        status="dry_run"
        validation_passed=true
        message="dry run emitted signoff manifests only"
    else
        if [ "$expected_projection_json" = "null" ] || jq -en \
            --argjson expected "$expected_projection_json" \
            --argjson actual "$projection_json" \
            '$expected == $actual' >/dev/null; then
            validation_passed=true
        else
            status="failed"
            validation_passed=false
            script_exit_code=1
            message="report projection diverged from the contract"
        fi
    fi
    ended_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    local report_json
    report_json="$(jq -cn \
        --arg schema_version "$(report_schema_version)" \
        --arg contract_version "$(contract_version)" \
        --arg scenario_id "$SCENARIO" \
        --arg description "$(jq -r '.description' <<<"$scenario_json")" \
        --arg mode "$MODE" \
        --arg started_ts "$started_ts" \
        --arg ended_ts "$ended_ts" \
        --arg status "$status" \
        --arg message "$message" \
        --arg host_template_mode "$host_template_mode" \
        --argjson validation_passed "$validation_passed" \
        --argjson child_statuses "$child_statuses" \
        --argjson tracked_dirty_paths "$tracked_dirty_paths" \
        --argjson objective_coverage "$objective_coverage" \
        --argjson report_projection "$projection_json" \
        --argjson generated_artifact_paths "$generated_artifact_paths" \
        '{
            schema_version: $schema_version,
            contract_version: $contract_version,
            scenario_id: $scenario_id,
            description: $description,
            mode: $mode,
            started_ts: $started_ts,
            ended_ts: $ended_ts,
            status: $status,
            message: $message,
            host_template_mode: ($host_template_mode == "true"),
            validation_passed: $validation_passed,
            child_artifacts: $child_statuses,
            tracked_dirty_paths: $tracked_dirty_paths,
            objective_coverage: $objective_coverage,
            generated_artifact_paths: $generated_artifact_paths,
            report_projection: $report_projection
        }')"

    printf '%s\n' "$report_json" >"$scenario_report_path"

    jq -cn \
        --arg schema_version "$(bundle_schema_version)" \
        --arg contract_version "$(contract_version)" \
        --arg scenario_id "$SCENARIO" \
        --arg artifact_path "$bundle_manifest_path" \
        --arg run_log_path "$run_log_path" \
        --arg mode "$MODE" \
        --arg status "$status" \
        --arg started_ts "$started_ts" \
        --arg ended_ts "$ended_ts" \
        --arg source_repo_hash "$(git -C "$PROJECT_ROOT" rev-parse --short=12 HEAD 2>/dev/null || printf unknown)" \
        --argjson validation_passed "$validation_passed" \
        --argjson tracked_dirty_paths "$tracked_dirty_paths" \
        --argjson objective_coverage "$objective_coverage" \
        --argjson report_projection "$projection_json" \
        --argjson generated_artifact_paths "$generated_artifact_paths" \
        '{
            schema_version: $schema_version,
            contract_version: $contract_version,
            scenario_id: $scenario_id,
            artifact_path: $artifact_path,
            run_log_path: $run_log_path,
            mode: $mode,
            status: $status,
            started_ts: $started_ts,
            ended_ts: $ended_ts,
            source_repo_hash: $source_repo_hash,
            validation_passed: $validation_passed,
            tracked_dirty_paths: $tracked_dirty_paths,
            objective_coverage: $objective_coverage,
            report_projection: $report_projection,
            generated_artifact_paths: $generated_artifact_paths
        }' >"$bundle_manifest_path"

    jq -cn \
        --arg schema_version "$(report_schema_version)" \
        --arg contract_version "$(contract_version)" \
        --arg scenario_id "$SCENARIO" \
        --arg artifact_path "$run_report_path" \
        --arg bundle_manifest_path "$bundle_manifest_path" \
        --arg run_log_path "$run_log_path" \
        --arg scenario_report_path "$scenario_report_path" \
        --arg mode "$MODE" \
        --arg status "$status" \
        --arg message "$message" \
        --argjson validation_passed "$validation_passed" \
        --argjson script_exit_code "$script_exit_code" \
        --argjson tracked_dirty_paths "$tracked_dirty_paths" \
        --argjson objective_coverage "$objective_coverage" \
        --argjson report_projection "$projection_json" \
        --argjson generated_artifact_paths "$generated_artifact_paths" \
        '{
            schema_version: $schema_version,
            contract_version: $contract_version,
            scenario_id: $scenario_id,
            artifact_path: $artifact_path,
            bundle_manifest_path: $bundle_manifest_path,
            run_log_path: $run_log_path,
            scenario_report_path: $scenario_report_path,
            mode: $mode,
            status: $status,
            message: $message,
            validation_passed: $validation_passed,
            script_exit_code: $script_exit_code,
            tracked_dirty_paths: $tracked_dirty_paths,
            objective_coverage: $objective_coverage,
            report_projection: $report_projection,
            generated_artifact_paths: $generated_artifact_paths
        }' >"$run_report_path"

    {
        printf 'scenario_id=%s\n' "$SCENARIO"
        printf 'contract_version=%s\n' "$(contract_version)"
        printf 'host_template_mode=%s\n' "$host_template_mode"
        printf 'child_artifact_count=%s\n' "$(jq -r '.child_artifact_count' <<<"$projection_json")"
        printf 'trusted_child_count=%s\n' "$(jq -r '.trusted_child_count' <<<"$projection_json")"
        printf 'fail_closed_child_count=%s\n' "$(jq -r '.fail_closed_child_count' <<<"$projection_json")"
        printf 'open_tracker_blocker_count=%s\n' "$(jq -r '.open_tracker_blocker_count' <<<"$projection_json")"
        printf 'dirty_cluster_fail_closed_count=%s\n' "$(jq -r '.dirty_cluster_fail_closed_count' <<<"$projection_json")"
        printf 'tracked_dirty_blocker_count=%s\n' "$(jq -r '.tracked_dirty_blocker_count' <<<"$projection_json")"
        printf 'source_skill_count=%s\n' "$(jq -r '.source_skill_count' <<<"$projection_json")"
        printf 'required_source_skill_count=%s\n' "$(jq -r '.required_source_skill_count' <<<"$projection_json")"
        printf 'missing_required_source_skill_count=%s\n' "$(jq -r '.missing_required_source_skill_count' <<<"$projection_json")"
        printf 'source_skill_phase_count=%s\n' "$(jq -r '.source_skill_phase_count' <<<"$projection_json")"
        printf 'required_source_skill_phase_count=%s\n' "$(jq -r '.required_source_skill_phase_count' <<<"$projection_json")"
        printf 'missing_required_source_skill_phase_count=%s\n' "$(jq -r '.missing_required_source_skill_phase_count' <<<"$projection_json")"
        printf 'objective_requirement_count=%s\n' "$(jq -r '.objective_requirement_count' <<<"$projection_json")"
        printf 'required_objective_requirement_count=%s\n' "$(jq -r '.required_objective_requirement_count' <<<"$projection_json")"
        printf 'covered_objective_requirement_count=%s\n' "$(jq -r '.covered_objective_requirement_count' <<<"$projection_json")"
        printf 'missing_required_objective_requirement_count=%s\n' "$(jq -r '.missing_required_objective_requirement_count' <<<"$projection_json")"
        printf 'unmapped_objective_requirement_count=%s\n' "$(jq -r '.unmapped_objective_requirement_count' <<<"$projection_json")"
        printf 'selected_bead_mapping_count=%s\n' "$(jq -r '.selected_bead_mapping_count' <<<"$projection_json")"
        printf 'missing_artifact_path_count=%s\n' "$(jq -r '.missing_artifact_path_count' <<<"$projection_json")"
        printf 'missing_runner_path_count=%s\n' "$(jq -r '.missing_runner_path_count' <<<"$projection_json")"
        printf 'objective_checklist_complete=%s\n' "$(jq -r '.objective_checklist_complete' <<<"$projection_json")"
        printf 'no_unexplained_artifacts=%s\n' "$(jq -r '.no_unexplained_artifacts' <<<"$projection_json")"
        printf 'missing_required_source_skills=%s\n' "$(jq -r '.missing_required_source_skills | join("|")' <<<"$objective_coverage")"
        printf 'missing_required_source_skill_phases=%s\n' "$(jq -r '.missing_required_source_skill_phases | join("|")' <<<"$objective_coverage")"
        printf 'missing_required_objective_requirement_ids=%s\n' "$(jq -r '.missing_required_objective_requirement_ids | join("|")' <<<"$objective_coverage")"
        printf 'unmapped_objective_requirement_ids=%s\n' "$(jq -r '.unmapped_objective_requirement_ids | join("|")' <<<"$objective_coverage")"
        printf 'tracked_dirty_paths=%s\n' "$(jq -r 'join("|")' <<<"$tracked_dirty_paths")"
        printf 'signoff_verdict=%s\n' "$(jq -r '.signoff_verdict' <<<"$projection_json")"
        printf 'generated_artifact_paths=%s\n' "$(jq -r 'join("|")' <<<"$generated_artifact_paths")"
        printf 'final_verdict=%s\n' "$(jq -r '.signoff_verdict' <<<"$projection_json")"
        printf 'MASSIVE_SWARM_SIGNOFF_REPORT_JSON_BEGIN\n'
        printf '%s\n' "$report_json"
        printf 'MASSIVE_SWARM_SIGNOFF_REPORT_JSON_END\n'
    } | tee "$run_log_path" >/dev/null

    printf 'Scenario: %s\n' "$SCENARIO"
    printf 'Mode: %s\n' "$MODE"
    printf 'Status: %s\n' "$status"
    printf 'Validation: %s\n' "$validation_passed"
    printf 'Bundle manifest: %s\n' "$bundle_manifest_path"
    printf 'Run report: %s\n' "$run_report_path"
    printf 'Scenario report: %s\n' "$scenario_report_path"

    if [ "$script_exit_code" -ne 0 ]; then
        exit "$script_exit_code"
    fi
}

main() {
    require_tools
    parse_args "$@"

    if [ "$LIST_ONLY" -eq 1 ]; then
        list_scenarios
        exit 0
    fi

    if [ -z "$SCENARIO" ]; then
        echo "FATAL: --scenario is required unless --list is used" >&2
        exit 1
    fi

    run_scenario
}

main "$@"
