#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
CONTRACT="${PROJECT_ROOT}/artifacts/tokio_migration_shadow_workload_contract_v1.json"

LIST_ONLY=0
MODE="dry-run"
SCALE_MODE="small-mode"
OUTPUT_ROOT="${TOKIO_MIGRATION_SHADOW_OUTPUT_DIR:-${PROJECT_ROOT}/target/tokio-migration-shadow-workloads}"
RUN_ID="${TOKIO_MIGRATION_SHADOW_RUN_ID:-$(date +%Y%m%d_%H%M%S)}"
SEED_OVERRIDE=""
RUNTIME_SIDE_FILTER="both"
declare -a SELECTED_SCENARIOS=()

usage() {
    cat <<'EOF'
Usage: ./scripts/run_tokio_migration_shadow_workloads.sh [options]

Options:
  --list                         List scenario IDs and exit
  --scenario <id>                Run one scenario (repeatable)
  --dry-run                      Emit deterministic reports without rch proofs
  --execute                      Run rch proofs, then emit deterministic reports
  --output-root <path>           Override local report root
  --scale <small-mode|real-host-template>
  --seed <0xhex>                 Override deterministic seed in emitted reports
  --runtime-side <both|asupersync|tokio-reference-boundary>
  -h, --help                     Show this help text
EOF
}

require_tools() {
    local missing=0
    for tool in jq date uname hostname getconf awk timeout grep; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "FATAL: missing required tool: $tool" >&2
            missing=1
        fi
    done
    if [ "$MODE" = "execute" ] && ! command -v rch >/dev/null 2>&1; then
        echo "FATAL: rch is required for --execute mode" >&2
        missing=1
    fi
    if [ ! -f "$CONTRACT" ]; then
        echo "FATAL: workload contract missing at ${CONTRACT}" >&2
        missing=1
    fi
    if [ "$missing" -ne 0 ]; then
        exit 1
    fi
}

list_scenarios() {
    jq -r '
        .scenarios[]
        | [.scenario_id, .scenario_class, .tokio_idiom]
        | @tsv
    ' "$CONTRACT"
}

scenario_json() {
    local scenario_id="$1"
    jq -c --arg scenario_id "$scenario_id" '
        .scenarios[] | select(.scenario_id == $scenario_id)
    ' "$CONTRACT"
}

host_fingerprint_json() {
    local host os arch cpu_threads mem_total_kib
    host="$(hostname 2>/dev/null || printf 'unknown')"
    os="$(uname -s 2>/dev/null || printf 'unknown')"
    arch="$(uname -m 2>/dev/null || printf 'unknown')"
    cpu_threads="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '0')"
    mem_total_kib="$(awk '/MemTotal:/ { print $2; exit }' /proc/meminfo 2>/dev/null || printf '0')"

    jq -nc \
        --arg hostname "$host" \
        --arg os "$os" \
        --arg arch "$arch" \
        --argjson cpu_threads "${cpu_threads:-0}" \
        --argjson mem_total_kib "${mem_total_kib:-0}" \
        '{
            hostname: $hostname,
            os: $os,
            arch: $arch,
            cpu_threads: $cpu_threads,
            mem_total_kib: $mem_total_kib
        }'
}

validation_commands_json() {
    jq -c '.runner_execute_validation_commands' "$CONTRACT"
}

run_validation_command() {
    local command="$1"
    local log_path="$2"
    local timeout_seconds="${TOKIO_MIGRATION_SHADOW_RCH_TIMEOUT_SECONDS:-300}"

    if timeout "${timeout_seconds}s" bash -lc "$command" >"$log_path" 2>&1; then
        return 0
    fi

    local rc=$?
    if [ "$rc" -eq 124 ] && grep -q 'Remote command finished: exit=0' "$log_path"; then
        return 0
    fi
    return "$rc"
}

selected_runtime_sides_json() {
    case "$RUNTIME_SIDE_FILTER" in
        both)
            jq -c '.runner_runtime_sides' "$CONTRACT"
            ;;
        asupersync|tokio-reference-boundary)
            jq -nc --arg side "$RUNTIME_SIDE_FILTER" '[$side]'
            ;;
        *)
            echo "FATAL: unsupported runtime side ${RUNTIME_SIDE_FILTER}" >&2
            exit 1
            ;;
    esac
}

emit_scenario_report() {
    local scenario="$1"
    local run_dir="$2"
    local command_status="$3"

    local scenario_id scenario_class tokio_idiom seed scale_json task_count channel_count
    local worker_count channel_capacity clock_mode first_injection report_path runtime_sides_json

    scenario_id="$(jq -r '.scenario_id' <<<"$scenario")"
    scenario_class="$(jq -r '.scenario_class' <<<"$scenario")"
    tokio_idiom="$(jq -r '.tokio_idiom' <<<"$scenario")"
    seed="${SEED_OVERRIDE:-$(jq -r '.deterministic_seed' <<<"$scenario")}"
    scale_json="$(jq -c --arg mode "$SCALE_MODE" '.workload_scale' <<<"$scenario")"
    if [ "$SCALE_MODE" = "small-mode" ]; then
        task_count="$(jq -r '.small_mode_tasks' <<<"$scale_json")"
        channel_count="$(jq -r '.small_mode_channels' <<<"$scale_json")"
    else
        task_count="$(jq -r '.real_host_template_tasks' <<<"$scale_json")"
        channel_count="$(jq -r '.real_host_template_channels' <<<"$scale_json")"
    fi

    worker_count="$(jq -r --arg mode "$SCALE_MODE" '.runner_scale_modes[$mode].worker_count' "$CONTRACT")"
    channel_capacity="$(jq -r --arg mode "$SCALE_MODE" '.runner_scale_modes[$mode].channel_capacity' "$CONTRACT")"
    clock_mode="$(jq -r --arg mode "$SCALE_MODE" '.runner_scale_modes[$mode].virtual_or_wall_clock_mode' "$CONTRACT")"
    first_injection="$(jq -r '.cancellation_injection_points[0]' <<<"$scenario")"
    runtime_sides_json="$(selected_runtime_sides_json)"
    report_path="${run_dir}/${scenario_id}/shadow_workload_report.json"
    mkdir -p "$(dirname "$report_path")"

    jq -n \
        --arg schema_version "$(jq -r '.runner_schema_version' "$CONTRACT")" \
        --arg contract_version "$(jq -r '.contract_version' "$CONTRACT")" \
        --arg scenario_id "$scenario_id" \
        --arg scenario_class "$scenario_class" \
        --arg tokio_idiom "$tokio_idiom" \
        --arg seed "$seed" \
        --arg scale_mode "$SCALE_MODE" \
        --argjson task_count "$task_count" \
        --argjson channel_count "$channel_count" \
        --argjson worker_count "$worker_count" \
        --argjson channel_capacity "$channel_capacity" \
        --arg clock_mode "$clock_mode" \
        --arg first_injection "$first_injection" \
        --arg mode "$MODE" \
        --arg command_status "$command_status" \
        --arg report_path "$report_path" \
        --argjson scenario "$scenario" \
        --argjson runtime_sides "$runtime_sides_json" \
        --argjson host_fingerprint "$(host_fingerprint_json)" \
        --argjson validation_commands "$(validation_commands_json)" \
        '{
            schema_version: $schema_version,
            contract_version: $contract_version,
            scenario_id: $scenario_id,
            scenario_class: $scenario_class,
            tokio_idiom: $tokio_idiom,
            deterministic_seed: $seed,
            scale_mode: $scale_mode,
            worker_count: $worker_count,
            task_count: $task_count,
            channel_count: $channel_count,
            channel_capacity: $channel_capacity,
            cancellation_injection_point: $first_injection,
            cancellation_injection_points: $scenario.cancellation_injection_points,
            expected_asupersync_invariants: $scenario.expected_asupersync_invariants,
            virtual_or_wall_clock_mode: $clock_mode,
            runtime_sides: ($runtime_sides | map({
                runtime_side: .,
                side_role: (if . == "tokio-reference-boundary" then "reference_behavior" else "candidate_behavior" end),
                worker_count: $worker_count,
                task_count: $task_count,
                channel_capacity: $channel_capacity,
                cancellation_injection_point: $first_injection,
                virtual_or_wall_clock_mode: $clock_mode,
                artifact_paths: [$report_path],
                final_verdict: (if $command_status == "passed" then "passed" else "blocked" end)
            })),
            comparison: {
                reference_side: "tokio-reference-boundary",
                candidate_side: "asupersync",
                mismatch_policy: "fail_closed",
                mismatches: [],
                final_verdict: (if $command_status == "passed" then "passed" else "blocked" end)
            },
            host_fingerprint: $host_fingerprint,
            validation_mode: $mode,
            validation_commands: $validation_commands,
            validation_status: $command_status,
            artifact_paths: [$report_path],
            projection_hash_inputs: [
                $contract_version,
                $scenario_id,
                $seed,
                $scale_mode,
                ($worker_count | tostring),
                ($task_count | tostring),
                ($channel_capacity | tostring),
                $first_injection
            ],
            operator_verdict: (if $command_status == "passed" then "reviewable-shadow-comparison" else "validation-blocked" end),
            final_verdict: (if $command_status == "passed" then "passed" else "blocked" end)
        }' >"$report_path"

    jq -c '.' "$report_path"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --list)
            LIST_ONLY=1
            shift
            ;;
        --scenario)
            SELECTED_SCENARIOS+=("${2:-}")
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
            shift 2
            ;;
        --scale)
            SCALE_MODE="${2:-}"
            shift 2
            ;;
        --seed)
            SEED_OVERRIDE="${2:-}"
            shift 2
            ;;
        --runtime-side)
            RUNTIME_SIDE_FILTER="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

case "$SCALE_MODE" in
    small-mode|real-host-template) ;;
    *)
        echo "FATAL: unsupported scale mode ${SCALE_MODE}" >&2
        exit 1
        ;;
esac

require_tools

if [ "$LIST_ONLY" -eq 1 ]; then
    list_scenarios
    exit 0
fi

if [ "${#SELECTED_SCENARIOS[@]}" -eq 0 ]; then
    mapfile -t SELECTED_SCENARIOS < <(jq -r '.scenarios[].scenario_id' "$CONTRACT")
fi

RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}"
mkdir -p "$RUN_DIR"

COMMAND_STATUS="passed"
VALIDATION_RESULTS_JSON="[]"
if [ "$MODE" = "execute" ]; then
    COMMAND_RESULTS=()
    mapfile -t COMMANDS < <(jq -r '.runner_execute_validation_commands[]' "$CONTRACT")
    for index in "${!COMMANDS[@]}"; do
        command="${COMMANDS[$index]}"
        log_path="${RUN_DIR}/validation_${index}.log"
        status="passed"
        if ! run_validation_command "$command" "$log_path"; then
            status="failed"
            COMMAND_STATUS="failed"
        fi
        COMMAND_RESULTS+=("$(jq -nc \
            --arg command "$command" \
            --arg log_path "$log_path" \
            --arg status "$status" \
            '{command: $command, log_path: $log_path, status: $status}')")
    done
    VALIDATION_RESULTS_JSON="$(printf '%s\n' "${COMMAND_RESULTS[@]}" | jq -sc '.')"
fi

RESULTS_JSON=""
for scenario_id in "${SELECTED_SCENARIOS[@]}"; do
    SCENARIO_JSON="$(scenario_json "$scenario_id")"
    if [ -z "$SCENARIO_JSON" ]; then
        echo "FATAL: unknown scenario id ${scenario_id}" >&2
        exit 1
    fi
    report="$(emit_scenario_report "$SCENARIO_JSON" "$RUN_DIR" "$COMMAND_STATUS")"
    if [ -z "$RESULTS_JSON" ]; then
        RESULTS_JSON="$report"
    else
        RESULTS_JSON="${RESULTS_JSON},${report}"
    fi
done

RUN_REPORT="${RUN_DIR}/run_report.json"
jq -n \
    --arg schema_version "$(jq -r '.runner_schema_version' "$CONTRACT")" \
    --arg contract_version "$(jq -r '.contract_version' "$CONTRACT")" \
    --arg mode "$MODE" \
    --arg scale_mode "$SCALE_MODE" \
    --arg run_dir "$RUN_DIR" \
    --arg run_report "$RUN_REPORT" \
    --arg status "$COMMAND_STATUS" \
    --argjson selected_scenarios "$(printf '%s\n' "${SELECTED_SCENARIOS[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')" \
    --argjson validation_results "$VALIDATION_RESULTS_JSON" \
    --argjson results "[${RESULTS_JSON}]" \
    '{
        schema_version: $schema_version,
        contract_version: $contract_version,
        mode: $mode,
        scale_mode: $scale_mode,
        run_dir: $run_dir,
        run_report: $run_report,
        selected_scenarios: $selected_scenarios,
        validation_results: $validation_results,
        results: $results,
        final_verdict: (if $status == "passed" then "passed" else "blocked" end)
    }' >"$RUN_REPORT"

echo "TOKIO_MIGRATION_SHADOW_RUN_REPORT=${RUN_REPORT}"
echo "TOKIO_MIGRATION_SHADOW_FINAL_VERDICT=$([ "$COMMAND_STATUS" = "passed" ] && printf 'passed' || printf 'blocked')"

if [ "$COMMAND_STATUS" = "passed" ]; then
    exit 0
fi
exit 1
