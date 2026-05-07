#!/usr/bin/env bash
set -euo pipefail

# Schema anchors for contract invariants:
# - controller-interference-validation-smoke-bundle-v1
# - controller-interference-validation-smoke-run-report-v1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONTRACT_ARTIFACT="${PROJECT_ROOT}/artifacts/controller_interference_validation_v1.json"
OUTPUT_ROOT="${CIV_SMOKE_OUTPUT_DIR:-${PROJECT_ROOT}/target/controller-interference-validation-smoke}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
LIST_ONLY=0
DRY_RUN=1
COMMAND_TIMEOUT_SECONDS="${CIV_SMOKE_TIMEOUT_SECONDS:-120}"
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"

declare -a SELECTED_SCENARIOS=()

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_controller_interference_validation_smoke.sh [options]

Options:
  --list                    List scenario IDs and exit
  --scenario <id>           Run one scenario (repeatable)
  --output-root <dir>       Override output root
  --dry-run                 Emit manifests without executing (default)
  --execute                 Execute cargo test scenarios
  --timeout-seconds <n>     Bound each executed scenario command (default: 120)
  -h, --help                Show help
USAGE
}

require_tools() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required" >&2; exit 1
    fi
    if ! [[ "$COMMAND_TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]]; then
        echo "FATAL: --timeout-seconds must be a positive integer" >&2; exit 1
    fi
    if [ ! -f "$CONTRACT_ARTIFACT" ]; then
        echo "FATAL: contract artifact missing at ${CONTRACT_ARTIFACT}" >&2; exit 1
    fi
    if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
        echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2; exit 1
    fi
    if [[ "$DRY_RUN" -eq 0 ]] && ! command -v timeout >/dev/null 2>&1; then
        echo "FATAL: timeout is required for --execute mode" >&2; exit 1
    fi
}

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
contract_version() { jq -r '.contract_version' "$CONTRACT_ARTIFACT"; }
bundle_schema_version() { jq -r '.runner_bundle_schema_version' "$CONTRACT_ARTIFACT"; }
report_schema_version() { jq -r '.runner_report_schema_version' "$CONTRACT_ARTIFACT"; }
bundle_required_fields_json() { jq -c '.runner_bundle_required_fields' "$CONTRACT_ARTIFACT"; }
report_required_fields_json() { jq -c '.runner_report_required_fields' "$CONTRACT_ARTIFACT"; }
env_fingerprint_fields_json() { jq -c '.env_fingerprint_fields' "$CONTRACT_ARTIFACT"; }
operator_bundle_fields_json() { jq -c '.operator_bundle_fields' "$CONTRACT_ARTIFACT"; }

markers_json_from_lines() {
    if [[ "$#" -eq 0 ]]; then
        printf '[]'
        return
    fi
    printf '%s\n' "$@" | jq -R . | jq -s -c .
}

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
    local sid="$1" scenario_json description command scenario_dir log_file summary_file started_ts ended_ts status
    local env_fingerprint active_controller_set shared_telemetry_fields knob_writes fallback_activation_counts decision_trace compose_verdict operator_explanation
    local required_log_markers_json missing_log_markers_json command_exit_code final_exit_code timeout_observed rch_remote_success_observed markers_ok scenario_filter
    local -a required_log_markers=()
    local -a missing_log_markers=()
    local -a command_args=()
    scenario_json="$(load_scenario_json "$sid")"
    [[ -z "$scenario_json" ]] && { echo "FATAL: unknown scenario: $sid" >&2; return 1; }
    description="$(jq -r '.description' <<<"$scenario_json")"
    case "$sid" in
        CIV-SMOKE-INTERFERENCE) scenario_filter="interference" ;;
        CIV-SMOKE-TIMESCALE) scenario_filter="timescale" ;;
        CIV-SMOKE-FALLBACK) scenario_filter="fallback" ;;
        CIV-SMOKE-SEQUENTIAL) scenario_filter="sequential" ;;
        *)
            echo "FATAL: unsupported scenario command mapping for ${sid}" >&2
            return 1
            ;;
    esac
    command_args=(
        "$RCH_BIN"
        exec
        --
        env
        "CARGO_INCREMENTAL=0"
        "CARGO_PROFILE_TEST_DEBUG=0"
        "RUSTFLAGS=-D warnings -C debuginfo=0"
        "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_controller_interference_validation"
        cargo
        test
        -p
        asupersync
        --test
        controller_interference_validation_contract
        "$scenario_filter"
        --
        --nocapture
    )
    printf -v command '%q ' "${command_args[@]}"
    command="${command% }"
    required_log_markers_json="$(jq -c '.required_log_markers // []' <<<"$scenario_json")"
    mapfile -t required_log_markers < <(jq -r '.required_log_markers[]? // empty' <<<"$scenario_json")
    env_fingerprint="$(jq -c '.env_fingerprint // {}' <<<"$scenario_json")"
    active_controller_set="$(jq -c '.active_controller_set // []' <<<"$scenario_json")"
    shared_telemetry_fields="$(jq -c '.shared_telemetry_fields // []' <<<"$scenario_json")"
    knob_writes="$(jq -c '.knob_writes // []' <<<"$scenario_json")"
    fallback_activation_counts="$(jq -c '.fallback_activation_counts // {}' <<<"$scenario_json")"
    decision_trace="$(jq -c '.decision_trace // []' <<<"$scenario_json")"
    compose_verdict="$(jq -r '.compose_verdict // "unclassified"' <<<"$scenario_json")"
    operator_explanation="$(jq -r '.operator_explanation // ""' <<<"$scenario_json")"
    scenario_dir="${RUN_DIR}/${sid}"; log_file="${scenario_dir}/run.log"; summary_file="${scenario_dir}/bundle_manifest.json"
    mkdir -p "$scenario_dir"
    started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ">>> Running scenario ${sid}"
    command_exit_code=0
    final_exit_code=0
    timeout_observed=false
    rch_remote_success_observed=false
    markers_ok=1
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf 'DRY_RUN scenario=%s\n' "$sid" >"$log_file"; status="dry_run"
    else
        (
            cd "$PROJECT_ROOT"
            timeout --kill-after=10s "${COMMAND_TIMEOUT_SECONDS}s" "${command_args[@]}"
        ) >"$log_file" 2>&1 || command_exit_code=$?
        if grep -Eq '^\[RCH\] local \(|falling back to local' "$log_file" 2>/dev/null; then
            command_exit_code=86
            printf 'FATAL: rch local fallback detected; refusing local cargo execution\n' >>"$log_file"
        fi
        if [[ "$command_exit_code" -eq 124 || "$command_exit_code" -eq 125 || "$command_exit_code" -eq 137 || "$command_exit_code" -eq 143 ]]; then
            timeout_observed=true
        fi
        if grep -Fq "Remote command finished: exit=0" "$log_file" && grep -Fq "test result: ok" "$log_file"; then
            rch_remote_success_observed=true
        fi
        for marker in "${required_log_markers[@]}"; do
            if ! grep -Fq -- "$marker" "$log_file"; then
                missing_log_markers+=("$marker")
            fi
        done
        if [[ "${#missing_log_markers[@]}" -ne 0 ]]; then
            markers_ok=0
        fi
        if [[ "$command_exit_code" -eq 0 && "$markers_ok" -eq 1 ]]; then
            status="passed"
        elif [[ "$timeout_observed" == "true" && "$rch_remote_success_observed" == "true" && "$markers_ok" -eq 1 ]]; then
            status="passed_after_rch_retrieval_timeout"
        else
            status="failed"
            final_exit_code="$command_exit_code"
            if [[ "$final_exit_code" -eq 0 ]]; then
                final_exit_code=1
            fi
        fi
    fi
    missing_log_markers_json="$(markers_json_from_lines "${missing_log_markers[@]}")"
    ended_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    {
        printf '\nCIV_TIMEOUT seconds=%s observed=%s command_exit_code=%s\n' "$COMMAND_TIMEOUT_SECONDS" "$timeout_observed" "$command_exit_code"
        printf 'CIV_RCH_REMOTE_SUCCESS observed=%s\n' "$rch_remote_success_observed"
        for marker in "${required_log_markers[@]}"; do
            if [[ "$DRY_RUN" -eq 1 ]]; then
                printf 'CIV_MARKER_CHECK status=skipped marker=%s\n' "$marker"
            elif printf '%s\n' "${missing_log_markers[@]}" | grep -Fxq -- "$marker"; then
                printf 'CIV_MARKER_CHECK status=missing marker=%s\n' "$marker"
            else
                printf 'CIV_MARKER_CHECK status=present marker=%s\n' "$marker"
            fi
        done
        printf 'CIV_SCENARIO_STATUS scenario=%s status=%s final_exit_code=%s\n' "$sid" "$status" "$final_exit_code"
    } >>"$log_file"
    cat >"$summary_file" <<JSON
{
  "schema_version": "$(json_escape "$(bundle_schema_version)")",
  "contract_version": "$(json_escape "$(contract_version)")",
  "scenario_id": "$(json_escape "$sid")",
  "description": "$(json_escape "$description")",
  "status": "$(json_escape "$status")",
  "exit_code": ${final_exit_code},
  "command_exit_code": ${command_exit_code},
  "timeout_seconds": ${COMMAND_TIMEOUT_SECONDS},
  "timeout_observed": ${timeout_observed},
  "rch_remote_success_observed": ${rch_remote_success_observed},
  "started_ts": "$(json_escape "$started_ts")",
  "ended_ts": "$(json_escape "$ended_ts")",
  "artifact_path": "$(json_escape "$summary_file")",
  "log_path": "$(json_escape "$log_file")",
  "command": "$(json_escape "$command")",
  "required_log_markers": ${required_log_markers_json},
  "missing_log_markers": ${missing_log_markers_json},
  "bundle_required_fields": $(bundle_required_fields_json),
  "env_fingerprint_fields": $(env_fingerprint_fields_json),
  "operator_bundle_fields": $(operator_bundle_fields_json),
  "env_fingerprint": ${env_fingerprint},
  "active_controller_set": ${active_controller_set},
  "shared_telemetry_fields": ${shared_telemetry_fields},
  "knob_writes": ${knob_writes},
  "fallback_activation_counts": ${fallback_activation_counts},
  "decision_trace": ${decision_trace},
  "compose_verdict": "$(json_escape "$compose_verdict")",
  "operator_explanation": "$(json_escape "$operator_explanation")"
}
JSON
    append_result "$(jq -c '.' "$summary_file")"
    [[ "$final_exit_code" -eq 0 ]]
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list) LIST_ONLY=1; shift ;;
        --scenario) SELECTED_SCENARIOS+=("${2:-}"); shift 2 ;;
        --output-root) OUTPUT_ROOT="${2:-}"; RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --execute) DRY_RUN=0; shift ;;
        --timeout-seconds) COMMAND_TIMEOUT_SECONDS="${2:-}"; shift 2 ;;
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
  "artifact_path": "$(json_escape "$RUN_REPORT")",
  "dry_run": $( [[ "$DRY_RUN" -eq 1 ]] && printf 'true' || printf 'false' ),
  "scenario_count": ${#SELECTED_SCENARIOS[@]},
  "report_required_fields": $(report_required_fields_json),
  "results": [${RESULTS_JSON}],
  "status": "$([ "$OVERALL_RC" -eq 0 ] && printf "passed" || printf "failed")"
}
JSON

echo ""
echo "==================================================================="
echo "   CONTROLLER INTERFERENCE VALIDATION SMOKE SUMMARY                "
echo "==================================================================="
echo "  Run dir:   ${RUN_DIR}"
echo "  Mode:      $([ "$DRY_RUN" -eq 1 ] && printf "DRY-RUN" || printf "EXECUTE")"
echo "  Status:    $([ "$OVERALL_RC" -eq 0 ] && printf "PASSED" || printf "FAILED")"
echo "==================================================================="

exit "$OVERALL_RC"
