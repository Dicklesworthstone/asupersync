#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONTRACT_ARTIFACT="${PROJECT_ROOT}/artifacts/runtime_ascension_closure_packet_v1.json"
OUTPUT_ROOT="${RACP_SMOKE_OUTPUT_DIR:-${PROJECT_ROOT}/target/runtime-ascension-closure-smoke}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
INVOKED_FROM="$(pwd)"
LIST_ONLY=0
DRY_RUN=1
RCH_BIN="${RCH_BIN:-$HOME/.local/bin/rch}"

declare -a SELECTED_SCENARIOS=()

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_runtime_ascension_closure_smoke.sh [options]

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
        echo "FATAL: jq is required" >&2
        exit 1
    fi
    if [[ ! -f "${CONTRACT_ARTIFACT}" ]]; then
        echo "FATAL: contract artifact missing at ${CONTRACT_ARTIFACT}" >&2
        exit 1
    fi
}

require_execute_tools() {
    if ! command -v "$RCH_BIN" >/dev/null 2>&1; then
        echo "FATAL: rch is required and was not found/executable at: ${RCH_BIN}" >&2
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
        | while IFS=$'\t' read -r sid desc; do
            printf '%-38s %s\n' "$sid" "$desc"
        done
}

load_scenario_json() {
    jq -c --arg sid "$1" '.smoke_scenarios[] | select(.scenario_id == $sid)' "$CONTRACT_ARTIFACT"
}

RESULTS_JSON=""
append_result() {
    if [[ -z "$RESULTS_JSON" ]]; then
        RESULTS_JSON="$1"
    else
        RESULTS_JSON="${RESULTS_JSON},$1"
    fi
}

scenario_command_args() {
    local sid="$1"
    local target_dir="${TMPDIR:-/tmp}/rch_target_runtime_ascension_closure"

    case "$sid" in
        RACP-SMOKE-PACKET)
            printf '%s\0' "$RCH_BIN" exec -- env CARGO_INCREMENTAL=0 "RUSTFLAGS=-D warnings" "CARGO_TARGET_DIR=${target_dir}" cargo test --test runtime_ascension_closure_packet_contract packet -- --nocapture
            ;;
        RACP-SMOKE-DEMOS)
            printf '%s\0' "$RCH_BIN" exec -- env CARGO_INCREMENTAL=0 "RUSTFLAGS=-D warnings" "CARGO_TARGET_DIR=${target_dir}" cargo test --test runtime_ascension_closure_packet_contract demo -- --nocapture
            ;;
        RACP-SMOKE-TRANSPORT)
            printf '%s\0' "$RCH_BIN" exec -- env CARGO_INCREMENTAL=0 "RUSTFLAGS=-D warnings" "CARGO_TARGET_DIR=${target_dir}" cargo test --test transport_frontier_benchmark_contract -- --nocapture
            ;;
        RACP-SMOKE-DOCTRINE)
            printf '%s\0' "$RCH_BIN" exec -- env CARGO_INCREMENTAL=0 "RUSTFLAGS=-D warnings" "CARGO_TARGET_DIR=${target_dir}" cargo test --test runtime_ascension_closure_packet_contract launch -- --nocapture
            ;;
        *)
            return 1
            ;;
    esac
}

run_scenario() {
    local sid="$1"
    local scenario_json
    local description
    local command
    local command_workdir
    local scenario_dir
    local log_file
    local summary_file
    local started_ts
    local ended_ts
    local status
    local rc
    local -a command_args

    scenario_json="$(load_scenario_json "$sid")"
    if [[ -z "$scenario_json" ]]; then
        echo "FATAL: unknown scenario: $sid" >&2
        return 1
    fi

    description="$(jq -r '.description' <<<"$scenario_json")"
    mapfile -d '' -t command_args < <(scenario_command_args "$sid") || {
        echo "FATAL: no argv mapping for scenario: $sid" >&2
        return 1
    }
    if [[ "${#command_args[@]}" -eq 0 ]]; then
        echo "FATAL: no argv mapping for scenario: $sid" >&2
        return 1
    fi
    printf -v command '%q ' "${command_args[@]}"
    command="${command% }"
    command_workdir="${PROJECT_ROOT}"
    scenario_dir="${RUN_DIR}/${sid}"
    log_file="${scenario_dir}/run.log"
    summary_file="${scenario_dir}/bundle_manifest.json"
    mkdir -p "$scenario_dir"
    started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    echo ">>> Running scenario ${sid}"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf 'DRY_RUN scenario=%s command=%s\n' "$sid" "$command" >"$log_file"
        rc=0
        status="dry_run"
    else
        rc=0
        (
            cd "$command_workdir"
            "${command_args[@]}"
        ) >"$log_file" 2>&1 || rc=$?
        if grep -Eq '^\[RCH\] local \(|falling back to local' "$log_file" 2>/dev/null; then
            printf '\nFATAL: rch local fallback detected; refusing local cargo execution\n' >>"$log_file"
            printf 'rch local fallback detected; refusing local cargo execution\n' > "${scenario_dir}/rch_local_fallback.txt"
            rc=86
        fi
        if [[ "$rc" -eq 0 ]]; then
            status="passed"
        else
            status="failed"
        fi
    fi

    ended_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    cat >"$summary_file" <<JSON
{
  "schema_version": "$(json_escape "$(bundle_schema_version)")",
  "contract_version": "$(json_escape "$(contract_version)")",
  "scenario_id": "$(json_escape "$sid")",
  "description": "$(json_escape "$description")",
  "status": "$(json_escape "$status")",
  "project_root": "$(json_escape "$PROJECT_ROOT")",
  "invoked_from": "$(json_escape "$INVOKED_FROM")",
  "command": "$(json_escape "$command")",
  "command_workdir": "$(json_escape "$command_workdir")",
  "log_file": "$(json_escape "$log_file")",
  "summary_file": "$(json_escape "$summary_file")",
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
            echo "Unknown: $1" >&2
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
require_execute_tools

if [[ "${#SELECTED_SCENARIOS[@]}" -eq 0 ]]; then
    mapfile -t SELECTED_SCENARIOS < <(jq -r '.smoke_scenarios[].scenario_id' "$CONTRACT_ARTIFACT")
fi

mkdir -p "$OUTPUT_ROOT"
OUTPUT_ROOT="$(cd "$OUTPUT_ROOT" && pwd)"
RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
mkdir -p "$RUN_DIR"
OVERALL_RC=0
for sid in "${SELECTED_SCENARIOS[@]}"; do
    run_scenario "$sid" || OVERALL_RC=1
done

RUN_REPORT="${RUN_DIR}/run_report.json"
GENERATED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat >"$RUN_REPORT" <<JSON
{
  "schema_version": "$(json_escape "$(report_schema_version)")",
  "contract_version": "$(json_escape "$(contract_version)")",
  "script_path": "scripts/run_runtime_ascension_closure_smoke.sh",
  "project_root": "$(json_escape "$PROJECT_ROOT")",
  "invoked_from": "$(json_escape "$INVOKED_FROM")",
  "command_workdir": "$(json_escape "$PROJECT_ROOT")",
  "generated_ts": "$(json_escape "$GENERATED_TS")",
  "run_dir": "$(json_escape "$RUN_DIR")",
  "dry_run": $( [[ "$DRY_RUN" -eq 1 ]] && printf 'true' || printf 'false' ),
  "results": [${RESULTS_JSON}],
  "status": "$([ "$OVERALL_RC" -eq 0 ] && printf "passed" || printf "failed")"
}
JSON

echo ""
echo "==================================================================="
echo "  RUNTIME ASCENSION CLOSURE PACKET SMOKE SUMMARY                   "
echo "==================================================================="
echo "  Run dir:   ${RUN_DIR}"
echo "  Report:    ${RUN_REPORT}"
echo "  Mode:      $([ "$DRY_RUN" -eq 1 ] && printf "DRY-RUN" || printf "EXECUTE")"
echo "  Status:    $([ "$OVERALL_RC" -eq 0 ] && printf "PASSED" || printf "FAILED")"
echo "==================================================================="

exit "$OVERALL_RC"
