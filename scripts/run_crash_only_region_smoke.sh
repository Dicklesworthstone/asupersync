#!/usr/bin/env bash
set -euo pipefail

# Schema anchors for contract invariants:
# - crash-only-region-smoke-bundle-v1
# - crash-only-region-smoke-run-report-v1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONTRACT_ARTIFACT="${PROJECT_ROOT}/artifacts/crash_only_region_semantics_v1.json"
OUTPUT_ROOT="${COR_SMOKE_OUTPUT_DIR:-${PROJECT_ROOT}/target/crash-only-region-smoke}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
LIST_ONLY=0
DRY_RUN=1
RCH_BIN="${RCH_BIN:-rch}"
RCH_WRAPPER_TIMEOUT="${RCH_WRAPPER_TIMEOUT:-600}"
RCH_LOCAL_FALLBACK_PATTERN='^\[RCH\] local \(|falling back to local|local fallback|fallback to local|executing locally'

declare -a SELECTED_SCENARIOS=()

usage() {
    cat <<'USAGE'
Usage: ./scripts/run_crash_only_region_smoke.sh [options]

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
    if [[ "$DRY_RUN" -eq 0 ]] && ! command -v "$RCH_BIN" >/dev/null 2>&1; then
        echo "FATAL: rch binary not found: ${RCH_BIN}" >&2
        exit 127
    fi
    if [[ "$DRY_RUN" -eq 0 ]] && ! command -v timeout >/dev/null 2>&1; then
        echo "FATAL: timeout is required" >&2
        exit 127
    fi
    if [ ! -f "$CONTRACT_ARTIFACT" ]; then
        echo "FATAL: contract artifact missing at ${CONTRACT_ARTIFACT}" >&2
        exit 1
    fi
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

shell_join() {
    printf '%q ' "$@"
}

contract_version() { jq -r '.contract_version' "$CONTRACT_ARTIFACT"; }
bundle_schema_version() { jq -r '.runner_bundle_schema_version' "$CONTRACT_ARTIFACT"; }
report_schema_version() { jq -r '.runner_report_schema_version' "$CONTRACT_ARTIFACT"; }

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

RESULTS_JSON=""
append_result() {
    if [[ -z "$RESULTS_JSON" ]]; then
        RESULTS_JSON="$1"
    else
        RESULTS_JSON="${RESULTS_JSON},$1"
    fi
}

run_scenario() {
    local sid="$1"
    local scenario_json
    scenario_json="$(load_scenario_json "$sid")"
    if [[ -z "$scenario_json" ]]; then
        echo "FATAL: unknown scenario id: ${sid}" >&2
        return 1
    fi

    local description contract_command test_filter
    description="$(jq -r '.description' <<<"$scenario_json")"
    contract_command="$(jq -r '.command' <<<"$scenario_json")"
    test_filter="$(jq -r '.test_filter // empty' <<<"$scenario_json")"

    local scenario_dir="${RUN_DIR}/${sid}"
    local log_file="${scenario_dir}/run.log"
    local summary_file="${scenario_dir}/bundle_manifest.json"
    local started_ts ended_ts status rc actual_command

    mkdir -p "$scenario_dir"
    started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    echo ">>> Running scenario ${sid}"
    echo "    description: ${description}"

    local safe_sid="${sid//[^A-Za-z0-9_]/_}"
    local -a command=(
        "$RCH_BIN" exec --
        env
        CARGO_INCREMENTAL=0
        CARGO_PROFILE_TEST_DEBUG=0
        "RUSTFLAGS=-C debuginfo=0"
        "CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_crash_only_region_${safe_sid}"
        "${CARGO_BIN:-cargo}" test -p asupersync --test crash_only_region_contract --features test-internals
    )
    if [[ -n "$test_filter" ]]; then
        command+=("$test_filter")
    fi
    command+=(-- --nocapture)
    actual_command="$(shell_join "${command[@]}")"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf 'DRY_RUN scenario=%s\ncommand=%s\n' "$sid" "$actual_command" | tee "$log_file" >/dev/null
        rc=0
        status="dry_run"
    else
        rc=0
        timeout "$RCH_WRAPPER_TIMEOUT" "${command[@]}" >"$log_file" 2>&1 || rc=$?
        if grep -Eiq "$RCH_LOCAL_FALLBACK_PATTERN" "$log_file"; then
            printf '\nFATAL: rch local fallback detected; refusing local cargo execution\n' >>"$log_file"
            printf 'rch local fallback detected; refusing local cargo execution\n' > "${scenario_dir}/rch_local_fallback.txt"
            rc=86
        fi
        status="$( [[ "$rc" -eq 0 ]] && printf "passed" || printf "failed" )"
    fi

    ended_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    cat >"$summary_file" <<JSON
{
  "schema_version": "$(json_escape "$(bundle_schema_version)")",
  "contract_version": "$(json_escape "$(contract_version)")",
  "scenario_id": "$(json_escape "$sid")",
  "description": "$(json_escape "$description")",
  "contract_command": "$(json_escape "$contract_command")",
  "executed_command": "$(json_escape "$actual_command")",
  "rch_binary": "$(json_escape "$RCH_BIN")",
  "validation_passed": $( [[ "$rc" -eq 0 ]] && printf 'true' || printf 'false' ),
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
  "rch_required": true,
  "rch_binary": "$(json_escape "$RCH_BIN")",
  "validation_passed": $( [[ "$OVERALL_RC" -eq 0 ]] && printf 'true' || printf 'false' ),
  "results": [${RESULTS_JSON}],
  "status": "$([ "$OVERALL_RC" -eq 0 ] && printf "passed" || printf "failed")"
}
JSON

echo ""
echo "==================================================================="
echo "       CRASH-ONLY REGION SMOKE SUMMARY                             "
echo "==================================================================="
echo "  Run dir:   ${RUN_DIR}"
echo "  Report:    ${RUN_REPORT}"
echo "  Mode:      $([ "$DRY_RUN" -eq 1 ] && printf "DRY-RUN" || printf "EXECUTE")"
echo "  Status:    $([ "$OVERALL_RC" -eq 0 ] && printf "PASSED" || printf "FAILED")"
echo "==================================================================="

exit "$OVERALL_RC"
