#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CORPUS_ARTIFACT="${PROJECT_ROOT}/artifacts/runtime_workload_corpus_v1.json"
OUTPUT_ROOT="${WORKLOAD_CORPUS_OUTPUT_DIR:-${PROJECT_ROOT}/target/workload-corpus}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
LIST_ONLY=0

declare -a SELECTED_WORKLOADS=()

usage() {
    cat <<'EOF'
Usage: ./scripts/run_runtime_workload_corpus.sh [options]

Options:
  --list                  List canonical workload IDs and exit
  --workload <id>         Run one workload (repeatable)
  --output-root <dir>     Override local bundle root (default: target/workload-corpus)
  -h, --help              Show help
EOF
}

require_tools() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "FATAL: jq is required for workload corpus execution" >&2
        exit 1
    fi
    if [ ! -f "$CORPUS_ARTIFACT" ]; then
        echo "FATAL: workload corpus artifact missing at ${CORPUS_ARTIFACT}" >&2
        exit 1
    fi
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

load_workload_json() {
    local workload_id="$1"
    jq -c --arg workload_id "$workload_id" '
        .workloads[]
        | select(.workload_id == $workload_id)
    ' "$CORPUS_ARTIFACT"
}

list_workloads() {
    jq -r '
        .workloads[]
        | [.workload_id, .family, .regime, .runtime_profile, .entrypoint_kind]
        | @tsv
    ' "$CORPUS_ARTIFACT" \
        | while IFS=$'\t' read -r workload_id family regime runtime_profile entrypoint_kind; do
            printf '%-20s family=%-18s regime=%-28s profile=%-20s kind=%s\n' \
                "$workload_id" \
                "$family" \
                "$regime" \
                "$runtime_profile" \
                "$entrypoint_kind"
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

run_workload() {
    local workload_id="$1"
    local workload_json
    workload_json="$(load_workload_json "$workload_id")"
    if [[ -z "$workload_json" ]]; then
        echo "FATAL: unknown workload id: ${workload_id}" >&2
        return 1
    fi

    local family scenario_id regime runtime_profile seed config_ref entrypoint_kind
    local entry_command replay_command expected_artifacts expected_evidence
    family="$(jq -r '.family' <<<"$workload_json")"
    scenario_id="$(jq -r '.scenario_id' <<<"$workload_json")"
    regime="$(jq -r '.regime' <<<"$workload_json")"
    runtime_profile="$(jq -r '.runtime_profile' <<<"$workload_json")"
    seed="$(jq -r '.seed' <<<"$workload_json")"
    config_ref="$(jq -r '.config_ref' <<<"$workload_json")"
    entrypoint_kind="$(jq -r '.entrypoint_kind' <<<"$workload_json")"
    entry_command="$(jq -r '.entry_command' <<<"$workload_json")"
    replay_command="$(jq -r '.replay_command' <<<"$workload_json")"
    expected_artifacts="$(jq -c '.expected_artifacts' <<<"$workload_json")"
    expected_evidence="$(jq -c '.expected_evidence' <<<"$workload_json")"

    local workload_dir="${RUN_DIR}/${workload_id}"
    local log_file="${workload_dir}/run.log"
    local summary_file="${workload_dir}/bundle_manifest.json"
    local started_ts ended_ts status rc

    mkdir -p "$workload_dir"
    started_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    export WORKLOAD_ID="$workload_id"
    export RUNTIME_PROFILE="$runtime_profile"
    export WORKLOAD_CONFIG_REF="$config_ref"
    export ASUPERSYNC_WORKLOAD_ID="$workload_id"
    export ASUPERSYNC_RUNTIME_PROFILE="$runtime_profile"
    export ASUPERSYNC_WORKLOAD_CONFIG_REF="$config_ref"
    export TEST_SEED="$seed"
    export ASUPERSYNC_SEED="$seed"

    echo ">>> Running ${workload_id}"
    echo "    family: ${family}"
    echo "    regime: ${regime}"
    echo "    profile: ${runtime_profile}"
    echo "    seed: ${seed}"
    echo "    command: ${entry_command}"

    set +e
    pushd "$PROJECT_ROOT" >/dev/null
    bash -lc "$entry_command" 2>&1 | tee "$log_file"
    rc=${PIPESTATUS[0]}
    popd >/dev/null
    set -e

    ended_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    status="failed"
    if [[ "$rc" -eq 0 ]]; then
        status="passed"
    fi

    cat >"$summary_file" <<EOF
{
  "schema_version": "runtime-workload-bundle-v1",
  "contract_version": "runtime-workload-corpus-v1",
  "workload_id": "$(json_escape "$workload_id")",
  "family": "$(json_escape "$family")",
  "scenario_id": "$(json_escape "$scenario_id")",
  "regime": "$(json_escape "$regime")",
  "runtime_profile": "$(json_escape "$runtime_profile")",
  "seed": "$(json_escape "$seed")",
  "workload_config_ref": "$(json_escape "$config_ref")",
  "entrypoint_kind": "$(json_escape "$entrypoint_kind")",
  "artifact_path": "$(json_escape "$summary_file")",
  "run_log_path": "$(json_escape "$log_file")",
  "entry_command": "$(json_escape "$entry_command")",
  "replay_command": "$(json_escape "$replay_command")",
  "status": "$(json_escape "$status")",
  "exit_code": ${rc},
  "started_ts": "$(json_escape "$started_ts")",
  "ended_ts": "$(json_escape "$ended_ts")",
  "expected_artifacts": ${expected_artifacts},
  "expected_evidence": ${expected_evidence}
}
EOF

    append_result "$(jq -c '.' "$summary_file")"

    [[ "$rc" -eq 0 ]]
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            LIST_ONLY=1
            shift
            ;;
        --workload)
            SELECTED_WORKLOADS+=("${2:-}")
            shift 2
            ;;
        --output-root)
            OUTPUT_ROOT="${2:-}"
            RUN_DIR="${OUTPUT_ROOT}/run_${TIMESTAMP}"
            shift 2
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
    list_workloads
    exit 0
fi

if [[ "${#SELECTED_WORKLOADS[@]}" -eq 0 ]]; then
    mapfile -t SELECTED_WORKLOADS < <(jq -r '.default_core_set[]' "$CORPUS_ARTIFACT")
fi

mkdir -p "$RUN_DIR"
RESULTS_JSON=""
OVERALL_RC=0

for workload_id in "${SELECTED_WORKLOADS[@]}"; do
    if ! run_workload "$workload_id"; then
        OVERALL_RC=1
    fi
done

RUN_REPORT="${RUN_DIR}/run_report.json"
cat >"$RUN_REPORT" <<EOF
{
  "schema_version": "runtime-workload-run-report-v1",
  "contract_version": "runtime-workload-corpus-v1",
  "artifact_path": "$(json_escape "$RUN_REPORT")",
  "run_dir": "$(json_escape "$RUN_DIR")",
  "selected_workloads": $(jq -nc --argjson ids "$(printf '%s\n' "${SELECTED_WORKLOADS[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')" '$ids'),
  "results": [${RESULTS_JSON}],
  "status": "$([ "$OVERALL_RC" -eq 0 ] && printf "passed" || printf "failed")"
}
EOF

echo ""
echo "==================================================================="
echo "                  RUNTIME WORKLOAD CORPUS SUMMARY                  "
echo "==================================================================="
echo "  Run dir:   ${RUN_DIR}"
echo "  Report:    ${RUN_REPORT}"
echo "  Status:    $([ "$OVERALL_RC" -eq 0 ] && printf "PASSED" || printf "FAILED")"
echo "==================================================================="

exit "$OVERALL_RC"
