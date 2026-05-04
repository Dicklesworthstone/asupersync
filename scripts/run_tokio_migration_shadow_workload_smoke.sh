#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
ARTIFACT="${PROJECT_ROOT}/artifacts/tokio_migration_shadow_workload_contract_v1.json"

LIST_ONLY=0
MODE="dry-run"
SCENARIO=""
OUTPUT_ROOT_OVERRIDE="${TOKIO_MIGRATION_SHADOW_OUTPUT_DIR:-}"
RUN_ID_OVERRIDE="${TOKIO_MIGRATION_SHADOW_RUN_ID:-}"
SCALE_MODE="small"
RUNTIME_SIDE="both"

usage() {
    cat <<'EOF'
Usage: ./scripts/run_tokio_migration_shadow_workload_smoke.sh [options]

Options:
  --list                     List available scenarios
  --scenario <id>            Run a specific scenario
  --dry-run                  Emit deterministic rows without workload execution
  --execute                  Execute the deterministic shadow workload contract
  --output-root <path>       Override output root
  --scale <mode>             small or real-host-template
  --runtime-side <side>      both, tokio-reference, or asupersync
  -h, --help                 Show this help text
EOF
}

require_tools() {
    local missing=0
    for tool in jq awk cksum date uname; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "FATAL: missing required tool: $tool" >&2
            missing=1
        fi
    done
    if [ "$missing" -ne 0 ]; then
        exit 1
    fi
}

contract_value() {
    jq -r "$1" "$ARTIFACT"
}

list_scenarios() {
    jq -r '.scenarios[] | [.scenario_id, .scenario_class] | @tsv' "$ARTIFACT"
}

default_scenario_id() {
    jq -r '.scenarios[0].scenario_id' "$ARTIFACT"
}

default_run_id() {
    local timestamp nanos pid
    timestamp="$(date +%Y%m%d_%H%M%S)"
    nanos="$(date +%N 2>/dev/null || printf '000000000')"
    pid="$$"
    printf '%s_%s_%s' "$timestamp" "$nanos" "$pid"
}

load_scenario_json() {
    local scenario_id="$1"
    jq -c --arg scenario_id "$scenario_id" \
        '.scenarios[] | select(.scenario_id == $scenario_id)' "$ARTIFACT"
}

host_fingerprint_json() {
    local host os kernel_release arch cpu_threads
    host="$(hostname 2>/dev/null || printf 'unknown')"
    os="$(uname -s 2>/dev/null || printf 'unknown')"
    kernel_release="$(uname -r 2>/dev/null || printf 'unknown')"
    arch="$(uname -m 2>/dev/null || printf 'unknown')"
    cpu_threads="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || printf '0')"

    jq -nc \
        --arg hostname "$host" \
        --arg os "$os" \
        --arg kernel_release "$kernel_release" \
        --arg arch "$arch" \
        --argjson cpu_threads "${cpu_threads:-0}" \
        '{
            hostname: $hostname,
            os: $os,
            kernel_release: $kernel_release,
            arch: $arch,
            cpu_threads: $cpu_threads
        }'
}

runtime_sides_json() {
    case "$RUNTIME_SIDE" in
        both)
            printf '["tokio-reference","asupersync"]'
            ;;
        tokio-reference|asupersync)
            jq -nc --arg side "$RUNTIME_SIDE" '[$side]'
            ;;
        *)
            echo "FATAL: unsupported --runtime-side ${RUNTIME_SIDE}" >&2
            exit 1
            ;;
    esac
}

scale_selector_json() {
    case "$SCALE_MODE" in
        small)
            jq -nc '{tasks_key:"small_mode_tasks", channels_key:"small_mode_channels", worker_floor:1, worker_cap:64}'
            ;;
        real-host-template)
            jq -nc '{tasks_key:"real_host_template_tasks", channels_key:"real_host_template_channels", worker_floor:64, worker_cap:256}'
            ;;
        *)
            echo "FATAL: unsupported --scale ${SCALE_MODE}" >&2
            exit 1
            ;;
    esac
}

projection_hash() {
    cksum | awk '{print $1}'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --list)
            LIST_ONLY=1
            shift
            ;;
        --scenario)
            SCENARIO="${2:-}"
            shift 2
            ;;
        --output-root)
            OUTPUT_ROOT_OVERRIDE="${2:-}"
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
        --scale)
            SCALE_MODE="${2:-}"
            shift 2
            ;;
        --runtime-side)
            RUNTIME_SIDE="${2:-}"
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

require_tools

if [ "$LIST_ONLY" -eq 1 ]; then
    list_scenarios
    exit 0
fi

if [ -z "$SCENARIO" ]; then
    SCENARIO="$(default_scenario_id)"
fi

SCENARIO_JSON="$(load_scenario_json "$SCENARIO")"
if [ -z "$SCENARIO_JSON" ]; then
    echo "FATAL: scenario ${SCENARIO} not found in ${ARTIFACT}" >&2
    exit 1
fi

CONTRACT_VERSION="$(contract_value '.contract_version')"
RUN_ID="${RUN_ID_OVERRIDE:-$(default_run_id)}"
OUTPUT_ROOT="${OUTPUT_ROOT_OVERRIDE:-${TMPDIR:-/tmp}/asupersync-tokio-migration-shadow}"
RUN_DIR="${OUTPUT_ROOT}/run_${RUN_ID}/${SCENARIO}"
REPORT_JSONL="${RUN_DIR}/shadow_workload_report.jsonl"
SUMMARY_JSON="${RUN_DIR}/shadow_workload_summary.json"
HOST_FINGERPRINT_JSON="$(host_fingerprint_json)"
RUNTIME_SIDES_JSON="$(runtime_sides_json)"
SCALE_SELECTOR_JSON="$(scale_selector_json)"
STARTED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p "$RUN_DIR"
: >"$REPORT_JSONL"

jq -rc \
    --arg contract_version "$CONTRACT_VERSION" \
    --arg mode "$MODE" \
    --arg scale_mode "$SCALE_MODE" \
    --arg report_jsonl "$REPORT_JSONL" \
    --arg summary_json "$SUMMARY_JSON" \
    --argjson runtime_sides "$RUNTIME_SIDES_JSON" \
    --argjson scale_selector "$SCALE_SELECTOR_JSON" \
    '
    . as $scenario
    | $scale_selector as $scale
    | ($scenario.workload_scale[$scale.tasks_key] | tonumber) as $task_count
    | ($scenario.workload_scale[$scale.channels_key] | tonumber) as $channel_capacity
    | (($task_count / 16) | floor) as $derived_workers
    | (if $derived_workers < $scale.worker_floor then $scale.worker_floor
       elif $derived_workers > $scale.worker_cap then $scale.worker_cap
       else $derived_workers end) as $worker_count
    | $runtime_sides[]
    | . as $runtime_side
    | {
        scenario_id: $scenario.scenario_id,
        contract_version: $contract_version,
        mode: $mode,
        runtime_side: $runtime_side,
        runtime_side_role: (if $runtime_side == "tokio-reference" then
            "canonical reference observation"
          else
            "asupersync invariant proof target"
          end),
        worker_count: $worker_count,
        task_count: $task_count,
        channel_capacity: $channel_capacity,
        deterministic_seed: $scenario.deterministic_seed,
        workload_scale_mode: $scale_mode,
        tokio_idiom: $scenario.tokio_idiom,
        tokio_source_surface: $scenario.tokio_source_surface,
        asupersync_rewrite: $scenario.asupersync_rewrite,
        cancellation_injection_point: $scenario.cancellation_injection_points[0],
        cancellation_injection_points: $scenario.cancellation_injection_points,
        expected_asupersync_invariants: $scenario.expected_asupersync_invariants,
        virtual_or_wall_clock_mode: (if $runtime_side == "asupersync" then
            "deterministic-virtual-contract"
          else
            "canonical-tokio-boundary-contract"
          end),
        artifact_paths: {
            report_jsonl: $report_jsonl,
            summary_json: $summary_json
        },
        final_verdict: (if $mode == "dry-run" then
            "dry_run_contract_row"
          elif $runtime_side == "asupersync" then
            "execute_requires_asupersync_invariant_rows"
          else
            "execute_records_tokio_reference_observation"
          end),
        operator_verdict: "review_required_before_migration",
        caveat_text: "This runner emits deterministic contract rows; capacity certification and rollout gating remain separate beads."
    }' <<<"$SCENARIO_JSON" |
while IFS= read -r row; do
    HASH_INPUT="$(jq -c '{scenario_id,contract_version,mode,runtime_side,worker_count,task_count,channel_capacity,deterministic_seed,workload_scale_mode,cancellation_injection_point,expected_asupersync_invariants,final_verdict}' <<<"$row")"
    HASH="$(printf '%s' "$HASH_INPUT" | projection_hash)"
    ROW_WITH_HASH="$(jq -c --arg projection_hash "$HASH" '. + {projection_hash: $projection_hash}' <<<"$row")"
    printf '%s\n' "$ROW_WITH_HASH" >>"$REPORT_JSONL"
    printf 'TOKIO_MIGRATION_SHADOW_WORKLOAD_ROW_JSON_BEGIN\n%s\nTOKIO_MIGRATION_SHADOW_WORKLOAD_ROW_JSON_END\n' "$ROW_WITH_HASH"
    jq -r '
        "SHADOW_WORKLOAD scenario_id=\(.scenario_id) contract_version=\(.contract_version) runtime_side=\(.runtime_side) worker_count=\(.worker_count) task_count=\(.task_count) channel_capacity=\(.channel_capacity) cancellation_injection_point=\(.cancellation_injection_point) clock_mode=\(.virtual_or_wall_clock_mode) artifact_path=\(.artifact_paths.report_jsonl) final_verdict=\(.final_verdict) projection_hash=\(.projection_hash)"
    ' <<<"$ROW_WITH_HASH"
done

ENDED_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

jq -s \
    --arg schema_version "tokio-migration-shadow-workload-run-summary-v1" \
    --arg contract_version "$CONTRACT_VERSION" \
    --arg scenario_id "$SCENARIO" \
    --arg mode "$MODE" \
    --arg scale_mode "$SCALE_MODE" \
    --arg started_at "$STARTED_TS" \
    --arg ended_at "$ENDED_TS" \
    --arg report_jsonl "$REPORT_JSONL" \
    --argjson host_fingerprint "$HOST_FINGERPRINT_JSON" \
    '{
        schema_version: $schema_version,
        contract_version: $contract_version,
        scenario_id: $scenario_id,
        mode: $mode,
        scale_mode: $scale_mode,
        started_at: $started_at,
        ended_at: $ended_at,
        host_fingerprint: $host_fingerprint,
        report_jsonl: $report_jsonl,
        row_count: length,
        runtime_sides: ([.[].runtime_side] | unique),
        final_verdicts: ([.[].final_verdict] | unique),
        projection_hashes: [.[].projection_hash]
    }' "$REPORT_JSONL" >"$SUMMARY_JSON"

printf 'TOKIO_MIGRATION_SHADOW_WORKLOAD_SUMMARY_JSON_BEGIN\n'
cat "$SUMMARY_JSON"
printf '\nTOKIO_MIGRATION_SHADOW_WORKLOAD_SUMMARY_JSON_END\n'
