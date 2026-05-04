#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
CONTRACT_ARTIFACT="${PROJECT_ROOT}/artifacts/jetstream_publish_backpressure_smoke_contract_v1.json"
OUTPUT_ROOT="${JETSTREAM_PUBLISH_BACKPRESSURE_SMOKE_OUTPUT_DIR:-${PROJECT_ROOT}/target/jetstream-publish-backpressure-smoke}"
ARTIFACT_ROOT="${JETSTREAM_PUBLISH_BACKPRESSURE_SMOKE_ARTIFACT_ROOT:-${PROJECT_ROOT}/.jetstream-publish-backpressure-smoke-artifacts}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
LIST_ONLY=0
MODE="dry-run"
SCENARIO=""

usage() {
    cat <<'EOF'
Usage: ./scripts/run_jetstream_publish_backpressure_smoke.sh [options]

Options:
  --list                     List available scenarios
  --scenario <id>            Run a specific scenario
  --dry-run                  Emit manifests without executing validation
  --execute                  Execute the deterministic backpressure audit
  --output-root <path>       Override output root
  -h, --help                 Show this help text
EOF
}

require_tools() {
    local missing=0
    for tool in jq sha256sum rg wc date; do
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
            printf '%-58s %s\n' "$scenario_id" "$description"
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

count_matches() {
    local pattern="$1"
    local path="$2"
    local count
    count="$(grep -E -c -- "$pattern" "$path" 2>/dev/null || true)"
    if [ -z "$count" ]; then
        count=0
    fi
    printf '%s' "$count"
}

count_fixed_matches() {
    local needle="$1"
    local path="$2"
    local count
    count="$(grep -F -c -- "$needle" "$path" 2>/dev/null || true)"
    if [ -z "$count" ]; then
        count=0
    fi
    printf '%s' "$count"
}

path_present() {
    local path="$1"
    if [ -f "${PROJECT_ROOT}/${path}" ]; then
        printf true
    else
        printf false
    fi
}

build_projection_json() {
    local scenario_json="$1"
    local audit_module_path consumer_flow_test_path target_source_path no_win_fallback
    local audit_should_panic_count consumer_flow_test_count explicit_pressure_signal_site_count
    local bounded_waiter_policy_present refusal_only_policy_present
    local multi_publisher_tail_evidence_present queueing_model
    local publish_wait_latency_p95_present publish_wait_latency_p99_present publish_wait_latency_p999_present
    local publish_wait_latency_p95_micros publish_wait_latency_p99_micros publish_wait_latency_p999_micros
    local missing_evidence_requirement_count scenario_mode operator_verdict tail_evidence_mode

    audit_module_path="$(jq -r '.audit_module_path' "$CONTRACT_ARTIFACT")"
    consumer_flow_test_path="$(jq -r '.consumer_flow_test_path' "$CONTRACT_ARTIFACT")"
    target_source_path="$(jq -r '.target_source_path' "$CONTRACT_ARTIFACT")"
    no_win_fallback="$(jq -r '.no_win_fallback' "$CONTRACT_ARTIFACT")"
    scenario_mode="$(jq -r '.scenario_mode' <<<"$scenario_json")"
    audit_should_panic_count="$(count_fixed_matches '#[should_panic' "${PROJECT_ROOT}/${audit_module_path}")"
    consumer_flow_test_count="$(count_fixed_matches '#[test]' "${PROJECT_ROOT}/${consumer_flow_test_path}")"
    explicit_pressure_signal_site_count="$(count_matches 'cx\\.pressure|check_pressure|pending_publishes|max_in_flight_publish|max_waiters' "${PROJECT_ROOT}/${target_source_path}")"
    missing_evidence_requirement_count="$(jq -r '.missing_evidence_requirements | length' "$CONTRACT_ARTIFACT")"

    if rg -q -e 'pending_publishes|max_in_flight_publish|max_waiters|waiter_limit' "${PROJECT_ROOT}/${target_source_path}"; then
        bounded_waiter_policy_present=true
    else
        bounded_waiter_policy_present=false
    fi
    if rg -q -e 'DEFAULT_MAX_PUBLISH_WAITERS: usize = 0;' "${PROJECT_ROOT}/${target_source_path}"; then
        refusal_only_policy_present=true
    else
        refusal_only_policy_present=false
    fi
    if rg -q -e 'multi_publisher_tail_evidence_present|mg11_loss_system|cohort_tail_evidence' "${PROJECT_ROOT}/${target_source_path}" "${PROJECT_ROOT}/${audit_module_path}" "${PROJECT_ROOT}/${consumer_flow_test_path}"; then
        multi_publisher_tail_evidence_present=true
        queueing_model="mg11_loss_system"
    else
        multi_publisher_tail_evidence_present=false
        queueing_model="absent"
    fi
    if rg -q -e 'publish_wait_latency_p95' "${PROJECT_ROOT}/${target_source_path}" "${PROJECT_ROOT}/${audit_module_path}" "${PROJECT_ROOT}/${consumer_flow_test_path}"; then
        publish_wait_latency_p95_present=true
    else
        publish_wait_latency_p95_present=false
    fi
    if rg -q -e 'publish_wait_latency_p99' "${PROJECT_ROOT}/${target_source_path}" "${PROJECT_ROOT}/${audit_module_path}" "${PROJECT_ROOT}/${consumer_flow_test_path}"; then
        publish_wait_latency_p99_present=true
    else
        publish_wait_latency_p99_present=false
    fi
    if rg -q -e 'publish_wait_latency_p999' "${PROJECT_ROOT}/${target_source_path}" "${PROJECT_ROOT}/${audit_module_path}" "${PROJECT_ROOT}/${consumer_flow_test_path}"; then
        publish_wait_latency_p999_present=true
    else
        publish_wait_latency_p999_present=false
    fi

    tail_evidence_mode="absent"
    publish_wait_latency_p95_micros=0
    publish_wait_latency_p99_micros=0
    publish_wait_latency_p999_micros=0
    if [ "$refusal_only_policy_present" = "true" ] \
        && [ "$publish_wait_latency_p95_present" = "true" ] \
        && [ "$publish_wait_latency_p99_present" = "true" ] \
        && [ "$publish_wait_latency_p999_present" = "true" ]; then
        tail_evidence_mode="zero_wait_refusal_only"
    fi

    operator_verdict="fail_closed"
    if [ "$audit_should_panic_count" -eq 0 ] \
        && [ "$explicit_pressure_signal_site_count" -gt 0 ] \
        && [ "$bounded_waiter_policy_present" = "true" ] \
        && [ "$publish_wait_latency_p95_present" = "true" ] \
        && [ "$publish_wait_latency_p99_present" = "true" ] \
        && [ "$publish_wait_latency_p999_present" = "true" ] \
        && [ "$missing_evidence_requirement_count" -eq 0 ]; then
        operator_verdict="ready_for_rch"
    fi

    local projection_without_hash projection_hash
    projection_without_hash="$(jq -cn \
        --arg scenario_mode "$scenario_mode" \
        --argjson audit_should_panic_count "$audit_should_panic_count" \
        --argjson consumer_flow_test_count "$consumer_flow_test_count" \
        --argjson explicit_pressure_signal_site_count "$explicit_pressure_signal_site_count" \
        --argjson bounded_waiter_policy_present "$bounded_waiter_policy_present" \
        --argjson refusal_only_policy_present "$refusal_only_policy_present" \
        --argjson multi_publisher_tail_evidence_present "$multi_publisher_tail_evidence_present" \
        --arg queueing_model "$queueing_model" \
        --arg tail_evidence_mode "$tail_evidence_mode" \
        --argjson publish_wait_latency_p95_present "$publish_wait_latency_p95_present" \
        --argjson publish_wait_latency_p99_present "$publish_wait_latency_p99_present" \
        --argjson publish_wait_latency_p999_present "$publish_wait_latency_p999_present" \
        --argjson publish_wait_latency_p95_micros "$publish_wait_latency_p95_micros" \
        --argjson publish_wait_latency_p99_micros "$publish_wait_latency_p99_micros" \
        --argjson publish_wait_latency_p999_micros "$publish_wait_latency_p999_micros" \
        --argjson missing_evidence_requirement_count "$missing_evidence_requirement_count" \
        --arg no_win_fallback "$no_win_fallback" \
        --arg operator_verdict "$operator_verdict" \
        '{
            scenario_mode: $scenario_mode,
            audit_should_panic_count: $audit_should_panic_count,
            consumer_flow_test_count: $consumer_flow_test_count,
            explicit_pressure_signal_site_count: $explicit_pressure_signal_site_count,
            bounded_waiter_policy_present: $bounded_waiter_policy_present,
            refusal_only_policy_present: $refusal_only_policy_present,
            multi_publisher_tail_evidence_present: $multi_publisher_tail_evidence_present,
            queueing_model: $queueing_model,
            tail_evidence_mode: $tail_evidence_mode,
            publish_wait_latency_p95_present: $publish_wait_latency_p95_present,
            publish_wait_latency_p99_present: $publish_wait_latency_p99_present,
            publish_wait_latency_p999_present: $publish_wait_latency_p999_present,
            publish_wait_latency_p95_micros: $publish_wait_latency_p95_micros,
            publish_wait_latency_p99_micros: $publish_wait_latency_p99_micros,
            publish_wait_latency_p999_micros: $publish_wait_latency_p999_micros,
            missing_evidence_requirement_count: $missing_evidence_requirement_count,
            no_win_fallback: $no_win_fallback,
            operator_verdict: $operator_verdict
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
    scenario_report_path="${ARTIFACT_ROOT}/run_${TIMESTAMP}/${SCENARIO}/jetstream_publish_backpressure_report.json"

    mkdir -p "$scenario_dir"
    mkdir -p "$(dirname "$scenario_report_path")"

    local projection_json expected_projection_json validation_passed status message script_exit_code
    local started_ts ended_ts generated_artifact_paths audit_module_path consumer_flow_test_path target_source_path
    projection_json="$(build_projection_json "$scenario_json")"
    expected_projection_json="$(jq -c '.expected_report_projection' <<<"$scenario_json")"
    audit_module_path="$(jq -r '.audit_module_path' "$CONTRACT_ARTIFACT")"
    consumer_flow_test_path="$(jq -r '.consumer_flow_test_path' "$CONTRACT_ARTIFACT")"
    target_source_path="$(jq -r '.target_source_path' "$CONTRACT_ARTIFACT")"
    generated_artifact_paths="$(jq -cn \
        --arg bundle_manifest_path "$bundle_manifest_path" \
        --arg run_report_path "$run_report_path" \
        --arg scenario_report_path "$scenario_report_path" \
        '[ $bundle_manifest_path, $run_report_path, $scenario_report_path ]')"

    started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    status="passed"
    validation_passed=false
    script_exit_code=0
    message="JetStream publish backpressure audit matched the contract"
    if [ "$MODE" = "dry-run" ]; then
        status="dry_run"
        validation_passed=true
        message="dry run emitted JetStream publish backpressure manifests only"
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
            message="JetStream publish backpressure projection diverged from the contract"
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
        --arg audit_module_path "$audit_module_path" \
        --arg consumer_flow_test_path "$consumer_flow_test_path" \
        --arg target_source_path "$target_source_path" \
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
            audit_module_path: $audit_module_path,
            consumer_flow_test_path: $consumer_flow_test_path,
            target_source_path: $target_source_path,
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
        printf 'scenario_mode=%s\n' "$(jq -r '.scenario_mode' <<<"$scenario_json")"
        printf 'audit_module_path=%s\n' "$audit_module_path"
        printf 'consumer_flow_test_path=%s\n' "$consumer_flow_test_path"
        printf 'target_source_path=%s\n' "$target_source_path"
        printf 'audit_should_panic_count=%s\n' "$(jq -r '.audit_should_panic_count' <<<"$projection_json")"
        printf 'consumer_flow_test_count=%s\n' "$(jq -r '.consumer_flow_test_count' <<<"$projection_json")"
        printf 'explicit_pressure_signal_site_count=%s\n' "$(jq -r '.explicit_pressure_signal_site_count' <<<"$projection_json")"
        printf 'bounded_waiter_policy_present=%s\n' "$(jq -r '.bounded_waiter_policy_present' <<<"$projection_json")"
        printf 'refusal_only_policy_present=%s\n' "$(jq -r '.refusal_only_policy_present' <<<"$projection_json")"
        printf 'multi_publisher_tail_evidence_present=%s\n' "$(jq -r '.multi_publisher_tail_evidence_present' <<<"$projection_json")"
        printf 'queueing_model=%s\n' "$(jq -r '.queueing_model' <<<"$projection_json")"
        printf 'tail_evidence_mode=%s\n' "$(jq -r '.tail_evidence_mode' <<<"$projection_json")"
        printf 'publish_wait_latency_p95_present=%s\n' "$(jq -r '.publish_wait_latency_p95_present' <<<"$projection_json")"
        printf 'publish_wait_latency_p99_present=%s\n' "$(jq -r '.publish_wait_latency_p99_present' <<<"$projection_json")"
        printf 'publish_wait_latency_p999_present=%s\n' "$(jq -r '.publish_wait_latency_p999_present' <<<"$projection_json")"
        printf 'publish_wait_latency_p95_micros=%s\n' "$(jq -r '.publish_wait_latency_p95_micros' <<<"$projection_json")"
        printf 'publish_wait_latency_p99_micros=%s\n' "$(jq -r '.publish_wait_latency_p99_micros' <<<"$projection_json")"
        printf 'publish_wait_latency_p999_micros=%s\n' "$(jq -r '.publish_wait_latency_p999_micros' <<<"$projection_json")"
        printf 'missing_evidence_requirement_count=%s\n' "$(jq -r '.missing_evidence_requirement_count' <<<"$projection_json")"
        printf 'no_win_fallback=%s\n' "$(jq -r '.no_win_fallback' <<<"$projection_json")"
        printf 'operator_verdict=%s\n' "$(jq -r '.operator_verdict' <<<"$projection_json")"
        printf 'generated_artifact_paths=%s\n' "$(jq -r 'join("|")' <<<"$generated_artifact_paths")"
        printf 'JETSTREAM_PUBLISH_BACKPRESSURE_REPORT_JSON_BEGIN\n'
        printf '%s\n' "$report_json"
        printf 'JETSTREAM_PUBLISH_BACKPRESSURE_REPORT_JSON_END\n'
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
