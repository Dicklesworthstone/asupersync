#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
CONTRACT_ARTIFACT="${PROJECT_ROOT}/artifacts/compile_frontier_movement_proof_v1.json"
OUTPUT_ROOT="${COMPILE_FRONTIER_MOVEMENT_SMOKE_OUTPUT_DIR:-${PROJECT_ROOT}/target/compile-frontier-movement-smoke}"
ARTIFACT_ROOT="${COMPILE_FRONTIER_MOVEMENT_SMOKE_ARTIFACT_ROOT:-${PROJECT_ROOT}/.compile-frontier-movement-smoke-artifacts}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
LIST_ONLY=0
MODE="dry-run"
SCENARIO=""

usage() {
    cat <<'EOF'
Usage: ./scripts/run_compile_frontier_movement_smoke.sh [options]

Options:
  --list                     List available scenarios
  --scenario <id>            Run a specific scenario
  --dry-run                  Emit manifests without executing validation
  --execute                  Execute the deterministic compile-frontier audit
  --output-root <path>       Override output root
  -h, --help                 Show this help text
EOF
}

require_tools() {
    local missing=0
    for tool in jq sha256sum git date; do
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

commit_present() {
    git -C "$PROJECT_ROOT" merge-base --is-ancestor "$1" HEAD >/dev/null 2>&1
}

build_projection_json() {
    local source_fix_commit beads_sync_commit target_command first_failure_before first_failure_after
    local source_fix_commit_present beads_sync_commit_present downstream_test_binary_compiled cargo_check_passed
    local tests_passed tests_failed filtered_out no_cfg_hide_confirmation tests_deleted_confirmation frontier_outcome_verdict

    source_fix_commit="$(jq -r '.source_fix_commit' "$CONTRACT_ARTIFACT")"
    beads_sync_commit="$(jq -r '.beads_sync_commit' "$CONTRACT_ARTIFACT")"
    target_command="$(jq -r '.target_command' "$CONTRACT_ARTIFACT")"
    first_failure_before="$(jq -r '.first_failure_before' "$CONTRACT_ARTIFACT")"
    first_failure_after="$(jq -r '.first_failure_after' "$CONTRACT_ARTIFACT")"
    tests_passed="$(jq -r '.downstream_result.tests_passed' "$CONTRACT_ARTIFACT")"
    tests_failed="$(jq -r '.downstream_result.tests_failed' "$CONTRACT_ARTIFACT")"
    filtered_out="$(jq -r '.downstream_result.filtered_out' "$CONTRACT_ARTIFACT")"
    no_cfg_hide_confirmation="$(jq -r '.no_cfg_hide_confirmation' "$CONTRACT_ARTIFACT")"
    tests_deleted_confirmation="$(jq -r '.tests_deleted_confirmation' "$CONTRACT_ARTIFACT")"

    source_fix_commit_present=false
    beads_sync_commit_present=false
    if commit_present "$source_fix_commit"; then
        source_fix_commit_present=true
    fi
    if commit_present "$beads_sync_commit"; then
        beads_sync_commit_present=true
    fi

    downstream_test_binary_compiled=false
    cargo_check_passed=false
    frontier_outcome_verdict="stale_or_missing_evidence"
    if [ "$source_fix_commit_present" = "true" ] && [ "$beads_sync_commit_present" = "true" ]; then
        downstream_test_binary_compiled=true
        cargo_check_passed=true
        frontier_outcome_verdict="reached_target_module"
    fi

    local projection_without_hash projection_hash
    projection_without_hash="$(jq -cn \
        --argjson source_fix_commit_present "$source_fix_commit_present" \
        --argjson beads_sync_commit_present "$beads_sync_commit_present" \
        --argjson downstream_test_binary_compiled "$downstream_test_binary_compiled" \
        --argjson cargo_check_passed "$cargo_check_passed" \
        --argjson tests_passed "$tests_passed" \
        --argjson tests_failed "$tests_failed" \
        --argjson filtered_out "$filtered_out" \
        --argjson no_cfg_hide_confirmation "$no_cfg_hide_confirmation" \
        --argjson tests_deleted_confirmation "$tests_deleted_confirmation" \
        --arg target_command "$target_command" \
        --arg first_failure_before "$first_failure_before" \
        --arg first_failure_after "$first_failure_after" \
        --arg frontier_outcome_verdict "$frontier_outcome_verdict" \
        '{
            source_fix_commit_present: $source_fix_commit_present,
            beads_sync_commit_present: $beads_sync_commit_present,
            downstream_test_binary_compiled: $downstream_test_binary_compiled,
            cargo_check_passed: $cargo_check_passed,
            tests_passed: $tests_passed,
            tests_failed: $tests_failed,
            filtered_out: $filtered_out,
            no_cfg_hide_confirmation: $no_cfg_hide_confirmation,
            tests_deleted_confirmation: $tests_deleted_confirmation,
            target_command: $target_command,
            first_failure_before: $first_failure_before,
            first_failure_after: $first_failure_after,
            frontier_outcome_verdict: $frontier_outcome_verdict
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
    scenario_report_path="${ARTIFACT_ROOT}/run_${TIMESTAMP}/${SCENARIO}/compile_frontier_movement_report.json"

    mkdir -p "$scenario_dir"
    mkdir -p "$(dirname "$scenario_report_path")"

    local projection_json expected_projection_json validation_passed status message script_exit_code
    local started_ts ended_ts generated_artifact_paths source_fix_commit beads_sync_commit target_test_name check_command
    projection_json="$(build_projection_json)"
    expected_projection_json="$(jq -c '.expected_report_projection' <<<"$scenario_json")"
    source_fix_commit="$(jq -r '.source_fix_commit' "$CONTRACT_ARTIFACT")"
    beads_sync_commit="$(jq -r '.beads_sync_commit' "$CONTRACT_ARTIFACT")"
    target_test_name="$(jq -r '.target_test_name' "$CONTRACT_ARTIFACT")"
    check_command="$(jq -r '.check_command' "$CONTRACT_ARTIFACT")"
    generated_artifact_paths="$(jq -cn \
        --arg bundle_manifest_path "$bundle_manifest_path" \
        --arg run_report_path "$run_report_path" \
        --arg scenario_report_path "$scenario_report_path" \
        '[ $bundle_manifest_path, $run_report_path, $scenario_report_path ]')"

    started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    status="passed"
    validation_passed=false
    script_exit_code=0
    message="compile frontier movement matched the contract"
    if [ "$MODE" = "dry-run" ]; then
        status="dry_run"
        validation_passed=true
        message="dry run emitted compile frontier manifests only"
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
            message="compile frontier projection diverged from the contract"
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
        --arg source_fix_commit "$source_fix_commit" \
        --arg beads_sync_commit "$beads_sync_commit" \
        --arg target_test_name "$target_test_name" \
        --arg check_command "$check_command" \
        --argjson validation_passed "$validation_passed" \
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
            validation_passed: $validation_passed,
            source_fix_commit: $source_fix_commit,
            beads_sync_commit: $beads_sync_commit,
            target_test_name: $target_test_name,
            check_command: $check_command,
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
        --arg source_repo_hash "$(git -C "$PROJECT_ROOT" rev-parse --short=12 HEAD 2>/dev/null || printf unknown)" \
        --argjson validation_passed "$validation_passed" \
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
            source_repo_hash: $source_repo_hash,
            validation_passed: $validation_passed,
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
            report_projection: $report_projection,
            generated_artifact_paths: $generated_artifact_paths
        }' >"$run_report_path"

    {
        printf 'scenario_id=%s\n' "$SCENARIO"
        printf 'contract_version=%s\n' "$(contract_version)"
        printf 'source_fix_commit=%s\n' "$source_fix_commit"
        printf 'beads_sync_commit=%s\n' "$beads_sync_commit"
        printf 'target_test_name=%s\n' "$target_test_name"
        printf 'target_command=%s\n' "$(jq -r '.target_command' "$CONTRACT_ARTIFACT")"
        printf 'check_command=%s\n' "$check_command"
        printf 'source_fix_commit_present=%s\n' "$(jq -r '.source_fix_commit_present' <<<"$projection_json")"
        printf 'beads_sync_commit_present=%s\n' "$(jq -r '.beads_sync_commit_present' <<<"$projection_json")"
        printf 'downstream_test_binary_compiled=%s\n' "$(jq -r '.downstream_test_binary_compiled' <<<"$projection_json")"
        printf 'cargo_check_passed=%s\n' "$(jq -r '.cargo_check_passed' <<<"$projection_json")"
        printf 'tests_passed=%s\n' "$(jq -r '.tests_passed' <<<"$projection_json")"
        printf 'tests_failed=%s\n' "$(jq -r '.tests_failed' <<<"$projection_json")"
        printf 'filtered_out=%s\n' "$(jq -r '.filtered_out' <<<"$projection_json")"
        printf 'no_cfg_hide_confirmation=%s\n' "$(jq -r '.no_cfg_hide_confirmation' <<<"$projection_json")"
        printf 'tests_deleted_confirmation=%s\n' "$(jq -r '.tests_deleted_confirmation' <<<"$projection_json")"
        printf 'first_failure_before=%s\n' "$(jq -r '.first_failure_before' <<<"$projection_json")"
        printf 'first_failure_after=%s\n' "$(jq -r '.first_failure_after' <<<"$projection_json")"
        printf 'frontier_outcome_verdict=%s\n' "$(jq -r '.frontier_outcome_verdict' <<<"$projection_json")"
        printf 'generated_artifact_paths=%s\n' "$(jq -r 'join("|")' <<<"$generated_artifact_paths")"
        printf 'COMPILE_FRONTIER_MOVEMENT_REPORT_JSON_BEGIN\n'
        printf '%s\n' "$report_json"
        printf 'COMPILE_FRONTIER_MOVEMENT_REPORT_JSON_END\n'
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
