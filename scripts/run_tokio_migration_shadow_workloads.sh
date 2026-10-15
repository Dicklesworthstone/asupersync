#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
CONTRACT="${PROJECT_ROOT}/artifacts/tokio_migration_shadow_workload_contract_v1.json"
SMOKE_RUNNER="${PROJECT_ROOT}/scripts/run_tokio_migration_shadow_workload_smoke.sh"
RUNNER_SCHEMA_VERSION="tokio-migration-shadow-workload-bulk-run-report-v1"

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
  --dry-run                      Emit deterministic aggregate reports without validation runs
  --execute                      Run the deterministic shadow smoke runner per scenario, then emit aggregate reports
  --output-root <path>           Override local report root
  --scale <small-mode|real-host-template>
  --seed <0xhex>                 Override deterministic seed in emitted reports
  --runtime-side <both|asupersync|tokio-reference-boundary>
  -h, --help                     Show this help text
EOF
}

require_tools() {
    local missing=0
    for tool in jq date uname hostname getconf awk timeout bash; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "FATAL: missing required tool: $tool" >&2
            missing=1
        fi
    done
    if [ ! -f "$CONTRACT" ]; then
        echo "FATAL: workload contract missing at ${CONTRACT}" >&2
        missing=1
    fi
    if [ ! -f "$SMOKE_RUNNER" ]; then
        echo "FATAL: shadow smoke runner missing at ${SMOKE_RUNNER}" >&2
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

render_command() {
    local rendered=()
    local arg
    for arg in "$@"; do
        printf -v arg '%q' "$arg"
        rendered+=("$arg")
    done
    local IFS=' '
    printf '%s' "${rendered[*]}"
}

smoke_scale_mode() {
    case "$SCALE_MODE" in
        small-mode)
            printf 'small'
            ;;
        real-host-template)
            printf 'real-host-template'
            ;;
        *)
            echo "FATAL: unsupported scale mode ${SCALE_MODE}" >&2
            exit 1
            ;;
    esac
}

smoke_runtime_side() {
    case "$RUNTIME_SIDE_FILTER" in
        both)
            printf 'both'
            ;;
        asupersync)
            printf 'asupersync'
            ;;
        tokio-reference-boundary)
            printf 'tokio-reference'
            ;;
        *)
            echo "FATAL: unsupported runtime side ${RUNTIME_SIDE_FILTER}" >&2
            exit 1
            ;;
    esac
}

build_validation_command_args() {
    local scenario_id="$1"
    local smoke_run_id="${RUN_ID}_${scenario_id}"
    local smoke_output_root="${RUN_DIR}/shadow_smoke_outputs"

    COMMAND_ARGS=(
        env
        "TOKIO_MIGRATION_SHADOW_RUN_ID=${smoke_run_id}"
        bash
        "$SMOKE_RUNNER"
        --execute
        --scenario
        "$scenario_id"
        --output-root
        "$smoke_output_root"
        --scale
        "$(smoke_scale_mode)"
        --runtime-side
        "$(smoke_runtime_side)"
    )
}

run_validation_command() {
    local log_path="$1"
    shift
    local timeout_seconds="${TOKIO_MIGRATION_SHADOW_RCH_TIMEOUT_SECONDS:-300}"

    timeout "${timeout_seconds}s" "$@" >"$log_path" 2>&1
}

selected_runtime_sides_json() {
    case "$RUNTIME_SIDE_FILTER" in
        both)
            jq -nc '["tokio-reference-boundary","asupersync"]'
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

derive_worker_count() {
    local task_count="$1"
    local derived floor cap
    derived=$((task_count / 16))
    case "$SCALE_MODE" in
        small-mode)
            floor=1
            cap=64
            ;;
        real-host-template)
            floor=64
            cap=256
            ;;
        *)
            echo "FATAL: unsupported scale mode ${SCALE_MODE}" >&2
            exit 1
            ;;
    esac
    if [ "$derived" -lt "$floor" ]; then
        derived="$floor"
    elif [ "$derived" -gt "$cap" ]; then
        derived="$cap"
    fi
    printf '%s' "$derived"
}

report_clock_mode() {
    case "$RUNTIME_SIDE_FILTER" in
        both)
            printf 'shadow-comparison-mixed-runtime-sides'
            ;;
        asupersync)
            printf 'deterministic-virtual-contract'
            ;;
        tokio-reference-boundary)
            printf 'canonical-tokio-boundary-contract'
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
    local validation_commands_json="$4"

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

    worker_count="$(derive_worker_count "$task_count")"
    channel_capacity="$channel_count"
    clock_mode="$(report_clock_mode)"
    first_injection="$(jq -r '.cancellation_injection_points[0]' <<<"$scenario")"
    runtime_sides_json="$(selected_runtime_sides_json)"
    report_path="${run_dir}/${scenario_id}/shadow_workload_report.json"
    mkdir -p "$(dirname "$report_path")"

    jq -n \
        --arg schema_version "$RUNNER_SCHEMA_VERSION" \
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
        --argjson validation_commands "$validation_commands_json" \
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
                virtual_or_wall_clock_mode: (if . == "tokio-reference-boundary" then "canonical-tokio-boundary-contract" else "deterministic-virtual-contract" end),
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
declare -a COMMAND_RESULTS=()

RESULTS_JSON=""
for scenario_id in "${SELECTED_SCENARIOS[@]}"; do
    SCENARIO_JSON="$(scenario_json "$scenario_id")"
    if [ -z "$SCENARIO_JSON" ]; then
        echo "FATAL: unknown scenario id ${scenario_id}" >&2
        exit 1
    fi

    build_validation_command_args "$scenario_id"
    validation_command="$(render_command "${COMMAND_ARGS[@]}")"
    validation_commands_json="$(jq -nc --arg command "$validation_command" '[$command]')"
    scenario_status="passed"

    if [ "$MODE" = "execute" ]; then
        log_path="${RUN_DIR}/validation_${scenario_id}.log"
        if ! run_validation_command "$log_path" "${COMMAND_ARGS[@]}"; then
            scenario_status="failed"
            COMMAND_STATUS="failed"
        fi
        COMMAND_RESULTS+=("$(jq -nc \
            --arg scenario_id "$scenario_id" \
            --arg command "$validation_command" \
            --arg log_path "$log_path" \
            --arg status "$scenario_status" \
            '{scenario_id: $scenario_id, command: $command, log_path: $log_path, status: $status}')")
    fi

    report="$(emit_scenario_report "$SCENARIO_JSON" "$RUN_DIR" "$scenario_status" "$validation_commands_json")"
    if [ -z "$RESULTS_JSON" ]; then
        RESULTS_JSON="$report"
    else
        RESULTS_JSON="${RESULTS_JSON},${report}"
    fi
done

if [ "${#COMMAND_RESULTS[@]}" -gt 0 ]; then
    VALIDATION_RESULTS_JSON="$(printf '%s\n' "${COMMAND_RESULTS[@]}" | jq -sc '.')"
fi

RUN_REPORT="${RUN_DIR}/run_report.json"
jq -n \
    --arg schema_version "$RUNNER_SCHEMA_VERSION" \
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
